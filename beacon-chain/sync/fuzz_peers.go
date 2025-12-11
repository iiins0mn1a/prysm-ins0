package sync

import (
	"context"
	"math/rand"
	"time"

	fuzz "github.com/google/gofuzz"
	libp2ppeer "github.com/libp2p/go-libp2p/core/peer"
	"github.com/prysmaticlabs/prysm/v5/beacon-chain/p2p"
	p2ptypes "github.com/prysmaticlabs/prysm/v5/beacon-chain/p2p/types"
	pb "github.com/prysmaticlabs/prysm/v5/proto/prysm/v1alpha1"
)

// startPeerFuzzLoop is registered as the onConnected callback in the
// underlying p2p service. It is responsible for starting a per-peer
// fuzzing routine that can send messages to the given peer.
func (s *Service) startPeerFuzzLoop(ctx context.Context, id libp2ppeer.ID) {
	// Run the fuzz routine in a separate goroutine so that we never
	// block the p2p connection handler, even if the caller forgets
	// to spawn a goroutine.
	go s.peerFuzzRoutine(ctx, id)
}

// peerFuzzRoutine 是 PoS 中针对单个 peer 的基础 fuzzer 循环。
// 它会周期性地从该 peer 的历史请求中选取一些种子请求，进行轻量变异后重新发送。
func (s *Service) peerFuzzRoutine(ctx context.Context, id libp2ppeer.ID) {
	// 简单的频率控制：每 10ms 尝试一次。
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	f := fuzz.New().NilChance(0.1)

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

			// 1. 随机选择类型（当前只实现两个核心类型）。
			categories := []string{
				"BeaconBlocksByRangeReqMsgs",
				"BeaconBlocksByRootReqMsgs",
			}
			cat := categories[rand.Intn(len(categories))]

			switch cat {
			case "BeaconBlocksByRangeReqMsgs":
				fuzzBeaconBlocksByRangeReq(ctx, s, id, recs, f)
			case "BeaconBlocksByRootReqMsgs":
				fuzzBeaconBlocksByRootReq(ctx, s, id, recs, f)
			}
		}
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
	orig := seeds[rand.Intn(len(seeds))]
	if orig == nil {
		return
	}

	// 直接在原始请求上做轻量扰动，对 fuzz 实验而言可以接受。
	f.Fuzz(&orig.Count)
	f.Fuzz(&orig.Step)
	if orig.Count == 0 {
		orig.Count = 1
	}

	_, _ = SendBeaconBlocksByRangeRequest(ctx, s.cfg.chain, s.cfg.p2p, id, orig, nil)
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
	orig := seeds[rand.Intn(len(seeds))]
	if orig == nil || len(*orig) == 0 {
		return
	}

	// 对原始请求进行扰动，制造不同的 root 组合。
	f.Fuzz(orig)

	_, _ = SendBeaconBlocksByRootRequest(ctx, s.cfg.clock, s.cfg.p2p, id, orig, nil)
}
