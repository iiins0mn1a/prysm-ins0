package sync

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"
	"time"

	fuzz "github.com/google/gofuzz"
	libp2ppeer "github.com/libp2p/go-libp2p/core/peer"
	"github.com/prysmaticlabs/prysm/v5/beacon-chain/p2p"
	p2ptypes "github.com/prysmaticlabs/prysm/v5/beacon-chain/p2p/types"
	"github.com/prysmaticlabs/prysm/v5/consensus-types/primitives"
	cryptorand "github.com/prysmaticlabs/prysm/v5/crypto/rand"
	pb "github.com/prysmaticlabs/prysm/v5/proto/prysm/v1alpha1"
	"github.com/prysmaticlabs/prysm/v5/time/slots"
	"google.golang.org/protobuf/proto"
)

// startPeerFuzzLoop is registered as the onConnected callback in the
// underlying p2p service. It is responsible for starting a per-peer
// fuzzing routine that can send messages to the given peer.
func (s *Service) startPeerFuzzLoop(ctx context.Context, id libp2ppeer.ID) {
	// Run the fuzz routine in a separate goroutine so that we never
	// block the p2p connection handler, even if the caller forgets
	// to spawn a goroutine.
	go s.peerFuzzRoutine(ctx, id)
	// Quick Return
}

// peerFuzzRoutine 是 PoS 中针对单个 peer 的基础 fuzzer 循环。
// 它会周期性地从该 peer 的历史请求中选取一些种子请求，进行轻量变异后重新发送。
func (s *Service) peerFuzzRoutine(ctx context.Context, id libp2ppeer.ID) {
	// Sleep for 10s for waiting
	time.Sleep(30 * time.Second)
	fmt.Printf("start Peer Fuzz Loop for peer %s\n", id.String())
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	f := fuzz.New().NilChance(0.1)
	const fuzzPerPeriod = 500

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ps, ok := s.cfg.p2p.(*p2p.Service)
			if !ok {
				continue
			}
			recs := ps.RecentRecordedMessages(id)
			if len(recs) == 0 {
				continue
			}

			for i := 0; i < fuzzPerPeriod; i++ {
				select {
				case <-ctx.Done():
					return
				default:
				}

				category := p2p.SelectRandomCategory(recs)
				if category == "" {
					continue
				}
				sendFuzzMessageByCategory(ctx, s, id, recs, category, f)
			}
			fmt.Printf("fuzzed %d messages for peer %s\n", fuzzPerPeriod, id.String())
		}
	}
}

// sendFuzzMessageByCategory 根据指定的 category 发送对应的 fuzz 消息。
// withFuzzRecovery wraps a fuzzing invocation with panic recovery so that
// a single bad fuzz input does not crash the whole beacon node.
func withFuzzRecovery(label string, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("[FUZZ_RECOVER] label=%s recovered panic=%v\n", label, r)
			debug.PrintStack()
		}
	}()
	fn()
}

func sendFuzzMessageByCategory(ctx context.Context, s *Service, id libp2ppeer.ID, recs []p2p.RecordedMessage, category string, f *fuzz.Fuzzer) {
	switch category {
	// RPC categories
	case "ConsensusStatusMsgs":
		withFuzzRecovery("ConsensusStatusMsgs", func() {
			fuzzConsensusStatus(ctx, s, id, recs, f)
		})
	case "ConsensusGoodbyeMsgs":
		withFuzzRecovery("ConsensusGoodbyeMsgs", func() {
			fuzzConsensusGoodbye(ctx, s, id, recs, f)
		})
	case "ConsensusPingMsgs":
		withFuzzRecovery("ConsensusPingMsgs", func() {
			fuzzConsensusPing(ctx, s, id, recs, f)
		})
	case "BeaconBlocksByRangeReqMsgs":
		withFuzzRecovery("BeaconBlocksByRangeReqMsgs", func() {
			fuzzBeaconBlocksByRangeReq(ctx, s, id, recs, f)
		})
	case "BeaconBlocksByRootReqMsgs":
		withFuzzRecovery("BeaconBlocksByRootReqMsgs", func() {
			fuzzBeaconBlocksByRootReq(ctx, s, id, recs, f)
		})
	case "MetadataV1ReqMsgs":
		withFuzzRecovery("MetadataV1ReqMsgs", func() {
			fuzzMetadataV1(ctx, s, id, recs, f)
		})
	case "MetadataV2ReqMsgs":
		withFuzzRecovery("MetadataV2ReqMsgs", func() {
			fuzzMetadataV2(ctx, s, id, recs, f)
		})
	case "BlobSidecarsByRangeReqMsgs":
		withFuzzRecovery("BlobSidecarsByRangeReqMsgs", func() {
			fuzzBlobSidecarsByRangeReq(ctx, s, id, recs, f)
		})
	case "BlobSidecarsByRootReqMsgs":
		withFuzzRecovery("BlobSidecarsByRootReqMsgs", func() {
			fuzzBlobSidecarsByRootReq(ctx, s, id, recs, f)
		})
	// Gossip categories - Blocks by fork
	case "BeaconBlocksMsgsPhase0", "BeaconBlocksAltairMsgs", "BeaconBlocksBellatrixMsgs",
		"BeaconBlocksCapellaMsgs", "BeaconBlocksDenebMsgs", "BeaconBlocksElectraMsgs":
		withFuzzRecovery("GossipBlock", func() {
			fuzzGossipBlock(ctx, s, recs, category, f)
		})
	// Gossip categories - Attestations
	case "AttestationsElectraMsgs", "AttestationsMsgs":
		withFuzzRecovery("GossipAttestation", func() {
			fuzzGossipAttestation(ctx, s, recs, category, f)
		})
	// Gossip categories - Aggregate attestations
	case "AggregateAndProofElectraMsgs", "AggregateAndProofMsgs":
		withFuzzRecovery("GossipAggregateAndProof", func() {
			fuzzGossipAggregateAndProof(ctx, s, recs, category, f)
		})
	// Gossip categories - Slashings & exits
	case "AttesterSlashingElectraMsgs", "AttesterSlashingMsgs":
		withFuzzRecovery("GossipAttesterSlashing", func() {
			fuzzGossipAttesterSlashing(ctx, s, recs, category, f)
		})
	case "ProposerSlashingMsgs":
		withFuzzRecovery("GossipProposerSlashing", func() {
			fuzzGossipProposerSlashing(ctx, s, recs, f)
		})
	case "VoluntaryExitMsgs":
		withFuzzRecovery("GossipVoluntaryExit", func() {
			fuzzGossipVoluntaryExit(ctx, s, recs, f)
		})
	// Gossip categories - Sync committee
	case "SyncCommitteeMsgs":
		withFuzzRecovery("GossipSyncCommittee", func() {
			fuzzGossipSyncCommittee(ctx, s, recs, f)
		})
	case "SyncContributionAndProofMsgs":
		withFuzzRecovery("GossipSyncContributionAndProof", func() {
			fuzzGossipSyncContributionAndProof(ctx, s, recs, f)
		})
	// Gossip categories - Other
	case "BLSToExecutionChangeMsgs":
		withFuzzRecovery("GossipBLSToExecutionChange", func() {
			fuzzGossipBLSToExecutionChange(ctx, s, recs, f)
		})
	case "BlobSidecarMsgs":
		withFuzzRecovery("GossipBlobSidecar", func() {
			fuzzGossipBlobSidecar(ctx, s, recs, f)
		})
	}
}

// fuzzBeaconBlocksByRangeReq: 2. 从 recorder 中按类型筛选一个随机种子；3. 轻量变异并重新发送。
func fuzzBeaconBlocksByRangeReq(ctx context.Context, s *Service, id libp2ppeer.ID, recs []p2p.RecordedMessage, f *fuzz.Fuzzer) {
	var seeds []*pb.BeaconBlocksByRangeRequest
	for _, r := range recs {
		if r.Category == "BeaconBlocksByRangeReqMsgs" {
			if v, ok := r.Message.(*pb.BeaconBlocksByRangeRequest); ok {
				seeds = append(seeds, v)
			}
		}
	}
	if len(seeds) == 0 {
		return
	}
	idx, err := randIndex(len(seeds))
	if err != nil {
		return
	}
	orig := seeds[idx]
	if orig == nil {
		return
	}

	// 直接在原始请求上做轻量扰动，对 fuzz 实验而言可以接受。
	f.Fuzz(&orig.Count)
	f.Fuzz(&orig.Step)
	if orig.Count == 0 {
		orig.Count = 1
	}

	fuzzCtx := p2p.WithFuzzSkipRecord(ctx)
	if _, err := SendBeaconBlocksByRangeRequest(fuzzCtx, s.cfg.chain, s.cfg.p2p, id, orig, nil); err != nil {
		// ignore errors — fuzzing may intentionally send invalid requests
	}
}

func fuzzBeaconBlocksByRootReq(ctx context.Context, s *Service, id libp2ppeer.ID, recs []p2p.RecordedMessage, f *fuzz.Fuzzer) {
	var seeds []*p2ptypes.BeaconBlockByRootsReq
	for _, r := range recs {
		if r.Category == "BeaconBlocksByRootReqMsgs" {
			if v, ok := r.Message.(*p2ptypes.BeaconBlockByRootsReq); ok {
				seeds = append(seeds, v)
			}
		}
	}
	if len(seeds) == 0 {
		return
	}
	idx, err := randIndex(len(seeds))
	if err != nil {
		return
	}
	orig := seeds[idx]
	if orig == nil || len(*orig) == 0 {
		return
	}

	// 对原始请求进行扰动：这里只 fuzz 部分元素顺序，而不是 deep-fuzz 整个 slice。
	// 通过简单交换若干 roots，制造不同组合，避免在 gofuzz 中触发复杂反射逻辑。
	if len(*orig) > 1 {
		// 选两个索引做交换
		i, err1 := randIndex(len(*orig))
		j, err2 := randIndex(len(*orig))
		if err1 == nil && err2 == nil && i != j {
			(*orig)[i], (*orig)[j] = (*orig)[j], (*orig)[i]
		}
	}

	fuzzCtx := p2p.WithFuzzSkipRecord(ctx)
	if _, err := SendBeaconBlocksByRootRequest(fuzzCtx, s.cfg.clock, s.cfg.p2p, id, orig, nil); err != nil {
		// ignore errors — fuzzing may intentionally send invalid requests
	}
}

// fuzzConsensusStatus 对 Status 消息进行 fuzzing
func fuzzConsensusStatus(ctx context.Context, s *Service, id libp2ppeer.ID, recs []p2p.RecordedMessage, f *fuzz.Fuzzer) {
	var seeds []*pb.Status
	for _, r := range recs {
		if r.Category == "ConsensusStatusMsgs" {
			if v, ok := r.Message.(*pb.Status); ok {
				seeds = append(seeds, v)
			}
		}
	}
	if len(seeds) == 0 {
		return
	}
	idx, err := randIndex(len(seeds))
	if err != nil {
		return
	}
	orig := seeds[idx]
	if orig == nil {
		return
	}

	// 对 Status 消息进行变异
	f.Fuzz(&orig.ForkDigest)
	f.Fuzz(&orig.FinalizedRoot)
	f.Fuzz(&orig.FinalizedEpoch)
	f.Fuzz(&orig.HeadRoot)
	f.Fuzz(&orig.HeadSlot)

	// 使用 p2p.Send 直接发送
	topic, err := p2p.TopicFromMessage(p2p.StatusMessageName, slots.ToEpoch(s.cfg.clock.CurrentSlot()))
	if err != nil {
		return
	}
	fuzzCtx := p2p.WithFuzzSkipRecord(ctx)
	if _, err := s.cfg.p2p.Send(fuzzCtx, orig, topic, id); err != nil {
		// ignore errors — fuzzing may intentionally send invalid requests
	}
}

// fuzzConsensusGoodbye 对 Goodbye 消息进行 fuzzing
func fuzzConsensusGoodbye(ctx context.Context, s *Service, id libp2ppeer.ID, recs []p2p.RecordedMessage, f *fuzz.Fuzzer) {
	var seeds []p2ptypes.RPCGoodbyeCode
	for _, r := range recs {
		if r.Category == "ConsensusGoodbyeMsgs" {
			if v, ok := r.Message.(p2ptypes.RPCGoodbyeCode); ok {
				seeds = append(seeds, v)
			} else if v64, ok := r.Message.(primitives.SSZUint64); ok {
				seeds = append(seeds, p2ptypes.RPCGoodbyeCode(v64))
			}
		}
	}
	if len(seeds) == 0 {
		return
	}
	idx, err := randIndex(len(seeds))
	if err != nil {
		return
	}
	code := seeds[idx]

	// 对 Goodbye code 进行变异
	f.Fuzz(&code)

	fuzzCtx := p2p.WithFuzzSkipRecord(ctx)
	if err := s.sendGoodByeMessage(fuzzCtx, code, id); err != nil {
		// ignore errors — fuzzing may intentionally send invalid requests
	}
}

// fuzzConsensusPing 对 Ping 消息进行 fuzzing
func fuzzConsensusPing(ctx context.Context, s *Service, id libp2ppeer.ID, recs []p2p.RecordedMessage, f *fuzz.Fuzzer) {
	var seeds []primitives.SSZUint64
	for _, r := range recs {
		if r.Category == "ConsensusPingMsgs" {
			if v, ok := r.Message.(primitives.SSZUint64); ok {
				seeds = append(seeds, v)
			} else if vp, ok := r.Message.(*primitives.SSZUint64); ok {
				seeds = append(seeds, *vp)
			}
		}
	}
	if len(seeds) == 0 {
		return
	}
	idx, err := randIndex(len(seeds))
	if err != nil {
		return
	}
	seq := seeds[idx]

	// 对 sequence number 进行变异
	f.Fuzz(&seq)

	// 使用 p2p.Send 直接发送
	topic, err := p2p.TopicFromMessage(p2p.PingMessageName, slots.ToEpoch(s.cfg.clock.CurrentSlot()))
	if err != nil {
		return
	}
	fuzzCtx := p2p.WithFuzzSkipRecord(ctx)
	if _, err := s.cfg.p2p.Send(fuzzCtx, &seq, topic, id); err != nil {
		// ignore errors — fuzzing may intentionally send invalid requests
	}
}

// fuzzMetadataV1 对 Metadata V1 请求进行 fuzzing
func fuzzMetadataV1(ctx context.Context, s *Service, id libp2ppeer.ID, recs []p2p.RecordedMessage, f *fuzz.Fuzzer) {
	// Metadata 请求不需要消息体，直接发送
	topic := p2p.RPCMetaDataTopicV1
	fuzzCtx := p2p.WithFuzzSkipRecord(ctx)
	if _, err := s.cfg.p2p.Send(fuzzCtx, new(interface{}), topic, id); err != nil {
		// ignore errors — fuzzing may intentionally send invalid requests
	}
}

// fuzzMetadataV2 对 Metadata V2 请求进行 fuzzing
func fuzzMetadataV2(ctx context.Context, s *Service, id libp2ppeer.ID, recs []p2p.RecordedMessage, f *fuzz.Fuzzer) {
	// Metadata 请求不需要消息体，直接发送
	topic := p2p.RPCMetaDataTopicV2
	fuzzCtx := p2p.WithFuzzSkipRecord(ctx)
	if _, err := s.cfg.p2p.Send(fuzzCtx, new(interface{}), topic, id); err != nil {
		// ignore errors — fuzzing may intentionally send invalid requests
	}
}

// fuzzBlobSidecarsByRangeReq 对 BlobSidecarsByRange 请求进行 fuzzing
func fuzzBlobSidecarsByRangeReq(ctx context.Context, s *Service, id libp2ppeer.ID, recs []p2p.RecordedMessage, f *fuzz.Fuzzer) {
	var seeds []*pb.BlobSidecarsByRangeRequest
	for _, r := range recs {
		if r.Category == "BlobSidecarsByRangeReqMsgs" {
			if v, ok := r.Message.(*pb.BlobSidecarsByRangeRequest); ok {
				seeds = append(seeds, v)
			}
		}
	}
	if len(seeds) == 0 {
		return
	}
	idx, err := randIndex(len(seeds))
	if err != nil {
		return
	}
	orig := seeds[idx]
	if orig == nil {
		return
	}

	// 对请求进行变异
	f.Fuzz(&orig.StartSlot)
	f.Fuzz(&orig.Count)
	if orig.Count == 0 {
		orig.Count = 1
	}

	ctxMap, err := ContextByteVersionsForValRoot(s.cfg.clock.GenesisValidatorsRoot())
	if err != nil {
		return
	}
	fuzzCtx := p2p.WithFuzzSkipRecord(ctx)
	if _, err := SendBlobsByRangeRequest(fuzzCtx, s.cfg.chain, s.cfg.p2p, id, ctxMap, orig); err != nil {
		// ignore errors — fuzzing may intentionally send invalid requests
	}
}

// fuzzBlobSidecarsByRootReq 对 BlobSidecarsByRoot 请求进行 fuzzing
func fuzzBlobSidecarsByRootReq(ctx context.Context, s *Service, id libp2ppeer.ID, recs []p2p.RecordedMessage, f *fuzz.Fuzzer) {
	var seeds []*p2ptypes.BlobSidecarsByRootReq
	for _, r := range recs {
		if r.Category == "BlobSidecarsByRootReqMsgs" {
			if v, ok := r.Message.(*p2ptypes.BlobSidecarsByRootReq); ok {
				seeds = append(seeds, v)
			}
		}
	}
	if len(seeds) == 0 {
		return
	}
	idx, err := randIndex(len(seeds))
	if err != nil {
		return
	}
	orig := seeds[idx]
	if orig == nil || len(*orig) == 0 {
		return
	}

	// 对请求进行变异
	f.Fuzz(orig)

	ctxMap, err := ContextByteVersionsForValRoot(s.cfg.clock.GenesisValidatorsRoot())
	if err != nil {
		return
	}
	ps, ok := s.cfg.p2p.(p2p.P2P)
	if !ok {
		return
	}
	fuzzCtx := p2p.WithFuzzSkipRecord(ctx)
	if _, err := SendBlobSidecarByRoot(fuzzCtx, s.cfg.chain, ps, id, ctxMap, orig); err != nil {
		// ignore errors — fuzzing may intentionally send invalid requests
	}
}

// randIndex returns a crypto-strong random index in [0, n).
// Uses a deterministic generator for performance (fuzzing doesn't require CSPRNG).
func randIndex(n int) (int, error) {
	if n <= 0 {
		return 0, errors.New("invalid range: n must be positive")
	}
	randGen := cryptorand.NewDeterministicGenerator()
	return randGen.Intn(n), nil
}

// ========== Gossip Message Fuzzing Functions ==========

// fuzzGossipBlock 对 Beacon Block 消息进行 fuzzing（所有 fork 版本）
func fuzzGossipBlock(ctx context.Context, s *Service, recs []p2p.RecordedMessage, category string, f *fuzz.Fuzzer) {
	var seeds []proto.Message
	for _, r := range recs {
		if r.Category == category {
			if msg, ok := r.Message.(proto.Message); ok {
				seeds = append(seeds, msg)
			}
		}
	}
	if len(seeds) == 0 {
		return
	}
	idx, err := randIndex(len(seeds))
	if err != nil {
		return
	}
	orig := seeds[idx]
	if orig == nil {
		return
	}

	// 对 Block 消息进行浅层字段级 fuzz，避免 deep-fuzz 整个块结构体。
	switch m := orig.(type) {
	case *pb.SignedBeaconBlock:
		if m.Block != nil {
			f.Fuzz(&m.Block.Slot)
			f.Fuzz(&m.Block.ProposerIndex)
			f.Fuzz(&m.Block.ParentRoot)
			f.Fuzz(&m.Block.StateRoot)
		}
		f.Fuzz(&m.Signature)
	case *pb.SignedBeaconBlockAltair:
		if m.Block != nil {
			f.Fuzz(&m.Block.Slot)
			f.Fuzz(&m.Block.ProposerIndex)
			f.Fuzz(&m.Block.ParentRoot)
			f.Fuzz(&m.Block.StateRoot)
		}
		f.Fuzz(&m.Signature)
	case *pb.SignedBeaconBlockBellatrix:
		if m.Block != nil {
			f.Fuzz(&m.Block.Slot)
			f.Fuzz(&m.Block.ProposerIndex)
			f.Fuzz(&m.Block.ParentRoot)
			f.Fuzz(&m.Block.StateRoot)
		}
		f.Fuzz(&m.Signature)
	case *pb.SignedBeaconBlockCapella:
		if m.Block != nil {
			f.Fuzz(&m.Block.Slot)
			f.Fuzz(&m.Block.ProposerIndex)
			f.Fuzz(&m.Block.ParentRoot)
			f.Fuzz(&m.Block.StateRoot)
		}
		f.Fuzz(&m.Signature)
	case *pb.SignedBeaconBlockDeneb:
		if m.Block != nil {
			f.Fuzz(&m.Block.Slot)
			f.Fuzz(&m.Block.ProposerIndex)
			f.Fuzz(&m.Block.ParentRoot)
			f.Fuzz(&m.Block.StateRoot)
		}
		f.Fuzz(&m.Signature)
	default:
		// 未显式支持的类型保留原始行为（如后续有新 fork，可单独收紧）。
		f.Fuzz(orig)
	}

	fuzzCtx := p2p.WithFuzzSkipRecord(ctx)
	if err := s.cfg.p2p.Broadcast(fuzzCtx, orig); err != nil {
		// ignore errors — fuzzing may intentionally send invalid messages
	}
}

// fuzzGossipAttestation 对 Attestation 消息进行 fuzzing
func fuzzGossipAttestation(ctx context.Context, s *Service, recs []p2p.RecordedMessage, category string, f *fuzz.Fuzzer) {
	var seeds []proto.Message
	for _, r := range recs {
		if r.Category == category {
			if msg, ok := r.Message.(proto.Message); ok {
				seeds = append(seeds, msg)
			}
		}
	}
	if len(seeds) == 0 {
		return
	}
	idx, err := randIndex(len(seeds))
	if err != nil {
		return
	}
	orig := seeds[idx]
	if orig == nil {
		return
	}

	switch m := orig.(type) {
	case *pb.Attestation:
		// 参考 PoW 下对 Header / Status 的做法，按字段 fuzz：
		// - 聚合 bitfield
		// - AttestationData 中的 slot / index / roots / epochs
		f.Fuzz(&m.AggregationBits)
		if m.Data != nil {
			f.Fuzz(&m.Data.Slot)
			f.Fuzz(&m.Data.CommitteeIndex)
			f.Fuzz(&m.Data.BeaconBlockRoot)
			if m.Data.Source != nil {
				f.Fuzz(&m.Data.Source.Epoch)
			}
			if m.Data.Target != nil {
				f.Fuzz(&m.Data.Target.Epoch)
			}
		}
		f.Fuzz(&m.Signature)
	default:
		f.Fuzz(orig)
	}

	// Attestation 需要通过 BroadcastAttestation 发送，需要 subnet
	// 这里简化处理，直接使用 Broadcast
	fuzzCtx := p2p.WithFuzzSkipRecord(ctx)
	if err := s.cfg.p2p.Broadcast(fuzzCtx, orig); err != nil {
		// ignore errors
	}
}

// fuzzGossipAggregateAndProof 对 AggregateAndProof 消息进行 fuzzing
func fuzzGossipAggregateAndProof(ctx context.Context, s *Service, recs []p2p.RecordedMessage, category string, f *fuzz.Fuzzer) {
	var seeds []proto.Message
	for _, r := range recs {
		if r.Category == category {
			if msg, ok := r.Message.(proto.Message); ok {
				seeds = append(seeds, msg)
			}
		}
	}
	if len(seeds) == 0 {
		return
	}
	idx, err := randIndex(len(seeds))
	if err != nil {
		return
	}
	orig := seeds[idx]
	if orig == nil {
		return
	}

	switch m := orig.(type) {
	case *pb.SignedAggregateAttestationAndProof:
		if m.Message != nil {
			f.Fuzz(&m.Message.AggregatorIndex)
			// 对内部 Aggregate.Attestation 做轻量字段级 fuzz。
			if m.Message.Aggregate != nil {
				f.Fuzz(&m.Message.Aggregate.AggregationBits)
				if m.Message.Aggregate.Data != nil {
					f.Fuzz(&m.Message.Aggregate.Data.Slot)
					f.Fuzz(&m.Message.Aggregate.Data.CommitteeIndex)
					f.Fuzz(&m.Message.Aggregate.Data.BeaconBlockRoot)
				}
			}
		}
		f.Fuzz(&m.Signature)
	default:
		f.Fuzz(orig)
	}

	if err := s.cfg.p2p.Broadcast(ctx, orig); err != nil {
		// ignore errors
	}
}

// fuzzGossipAttesterSlashing 对 AttesterSlashing 消息进行 fuzzing
func fuzzGossipAttesterSlashing(ctx context.Context, s *Service, recs []p2p.RecordedMessage, category string, f *fuzz.Fuzzer) {
	var seeds []proto.Message
	for _, r := range recs {
		if r.Category == category {
			if msg, ok := r.Message.(proto.Message); ok {
				seeds = append(seeds, msg)
			}
		}
	}
	if len(seeds) == 0 {
		return
	}
	idx, err := randIndex(len(seeds))
	if err != nil {
		return
	}
	orig := seeds[idx]
	if orig == nil {
		return
	}

	switch m := orig.(type) {
	case *pb.AttesterSlashing:
		// 只 fuzz 上一层结构，不直接 deep-fuzz IndexedAttestation，降低触发 nil-slice 问题概率。
		if m.Attestation_1 != nil {
			f.Fuzz(&m.Attestation_1.Signature)
		}
		if m.Attestation_2 != nil {
			f.Fuzz(&m.Attestation_2.Signature)
		}
	default:
		f.Fuzz(orig)
	}

	if err := s.cfg.p2p.Broadcast(ctx, orig); err != nil {
		// ignore errors
	}
}

// fuzzGossipProposerSlashing 对 ProposerSlashing 消息进行 fuzzing
func fuzzGossipProposerSlashing(ctx context.Context, s *Service, recs []p2p.RecordedMessage, f *fuzz.Fuzzer) {
	var seeds []*pb.ProposerSlashing
	for _, r := range recs {
		if r.Category == "ProposerSlashingMsgs" {
			if v, ok := r.Message.(*pb.ProposerSlashing); ok {
				seeds = append(seeds, v)
			}
		}
	}
	if len(seeds) == 0 {
		return
	}
	idx, err := randIndex(len(seeds))
	if err != nil {
		return
	}
	orig := seeds[idx]
	if orig == nil {
		return
	}

	// 对 ProposerSlashing 进行浅层 fuzz：不 deep-fuzz header，降低本地崩溃风险。
	if orig.Header_1 != nil {
		f.Fuzz(&orig.Header_1.Signature)
	}
	if orig.Header_2 != nil {
		f.Fuzz(&orig.Header_2.Signature)
	}

	if err := s.cfg.p2p.Broadcast(ctx, orig); err != nil {
		// ignore errors
	}
}

// fuzzGossipVoluntaryExit 对 VoluntaryExit 消息进行 fuzzing
func fuzzGossipVoluntaryExit(ctx context.Context, s *Service, recs []p2p.RecordedMessage, f *fuzz.Fuzzer) {
	var seeds []*pb.SignedVoluntaryExit
	for _, r := range recs {
		if r.Category == "VoluntaryExitMsgs" {
			if v, ok := r.Message.(*pb.SignedVoluntaryExit); ok {
				seeds = append(seeds, v)
			}
		}
	}
	if len(seeds) == 0 {
		return
	}
	idx, err := randIndex(len(seeds))
	if err != nil {
		return
	}
	orig := seeds[idx]
	if orig == nil {
		return
	}

	// 对 SignedVoluntaryExit 进行字段级 fuzz。
	if orig.Exit != nil {
		f.Fuzz(&orig.Exit.Epoch)
		f.Fuzz(&orig.Exit.ValidatorIndex)
	}
	f.Fuzz(&orig.Signature)

	if err := s.cfg.p2p.Broadcast(ctx, orig); err != nil {
		// ignore errors
	}
}

// fuzzGossipSyncCommittee 对 SyncCommittee 消息进行 fuzzing
func fuzzGossipSyncCommittee(ctx context.Context, s *Service, recs []p2p.RecordedMessage, f *fuzz.Fuzzer) {
	var seeds []*pb.SyncCommitteeMessage
	for _, r := range recs {
		if r.Category == "SyncCommitteeMsgs" {
			if v, ok := r.Message.(*pb.SyncCommitteeMessage); ok {
				seeds = append(seeds, v)
			}
		}
	}
	if len(seeds) == 0 {
		return
	}
	idx, err := randIndex(len(seeds))
	if err != nil {
		return
	}
	orig := seeds[idx]
	if orig == nil {
		return
	}

	// 字段级 fuzz，避免 deep-fuzz 整个 protobuf 结构体导致 gofuzz/SSZ 内部 panic。
	f.Fuzz(&orig.Slot)
	f.Fuzz(&orig.ValidatorIndex)
	f.Fuzz(&orig.Signature)
	// BlockRoot 可以视情况轻微扰动，当前保持原值以减少本地解码/验证风险。

	// SyncCommittee 需要通过 BroadcastSyncCommitteeMessage 发送，需要 subnet
	// 这里简化处理，直接使用 Broadcast
	fuzzCtx := p2p.WithFuzzSkipRecord(ctx)
	if err := s.cfg.p2p.Broadcast(fuzzCtx, orig); err != nil {
		// ignore errors
	}
}

// fuzzGossipSyncContributionAndProof 对 SyncContributionAndProof 消息进行 fuzzing
func fuzzGossipSyncContributionAndProof(ctx context.Context, s *Service, recs []p2p.RecordedMessage, f *fuzz.Fuzzer) {
	var seeds []*pb.SignedContributionAndProof
	for _, r := range recs {
		if r.Category == "SyncContributionAndProofMsgs" {
			if v, ok := r.Message.(*pb.SignedContributionAndProof); ok {
				seeds = append(seeds, v)
			}
		}
	}
	if len(seeds) == 0 {
		return
	}
	idx, err := randIndex(len(seeds))
	if err != nil {
		return
	}
	orig := seeds[idx]
	if orig == nil {
		return
	}

	// 对 SignedContributionAndProof 进行字段级 fuzz。
	if orig.Message != nil {
		f.Fuzz(&orig.Message.AggregatorIndex)
		f.Fuzz(&orig.Message.SelectionProof)
	}
	f.Fuzz(&orig.Signature)

	if err := s.cfg.p2p.Broadcast(ctx, orig); err != nil {
		// ignore errors
	}
}

// fuzzGossipBLSToExecutionChange 对 BLSToExecutionChange 消息进行 fuzzing
func fuzzGossipBLSToExecutionChange(ctx context.Context, s *Service, recs []p2p.RecordedMessage, f *fuzz.Fuzzer) {
	var seeds []*pb.SignedBLSToExecutionChange
	for _, r := range recs {
		if r.Category == "BLSToExecutionChangeMsgs" {
			if v, ok := r.Message.(*pb.SignedBLSToExecutionChange); ok {
				seeds = append(seeds, v)
			}
		}
	}
	if len(seeds) == 0 {
		return
	}
	idx, err := randIndex(len(seeds))
	if err != nil {
		return
	}
	orig := seeds[idx]
	if orig == nil {
		return
	}

	// 对 SignedBLSToExecutionChange 进行字段级 fuzz。
	if orig.Message != nil {
		f.Fuzz(&orig.Message.ValidatorIndex)
	}
	f.Fuzz(&orig.Signature)

	if err := s.cfg.p2p.Broadcast(ctx, orig); err != nil {
		// ignore errors
	}
}

// fuzzGossipBlobSidecar 对 BlobSidecar 消息进行 fuzzing
func fuzzGossipBlobSidecar(ctx context.Context, s *Service, recs []p2p.RecordedMessage, f *fuzz.Fuzzer) {
	var seeds []*pb.BlobSidecar
	for _, r := range recs {
		if r.Category == "BlobSidecarMsgs" {
			if v, ok := r.Message.(*pb.BlobSidecar); ok {
				seeds = append(seeds, v)
			}
		}
	}
	if len(seeds) == 0 {
		return
	}
	idx, err := randIndex(len(seeds))
	if err != nil {
		return
	}
	orig := seeds[idx]
	if orig == nil {
		return
	}

	// 对 BlobSidecar 进行字段级 fuzz，避免破坏内部 Merkle 证明结构。
	f.Fuzz(&orig.Index)
	f.Fuzz(&orig.Blob)
	f.Fuzz(&orig.KzgCommitment)
	f.Fuzz(&orig.KzgProof)

	// BlobSidecar 需要通过 BroadcastBlob 发送，需要 subnet
	// 这里简化处理，直接使用 Broadcast
	fuzzCtx := p2p.WithFuzzSkipRecord(ctx)
	if err := s.cfg.p2p.Broadcast(fuzzCtx, orig); err != nil {
		// ignore errors
	}
}
