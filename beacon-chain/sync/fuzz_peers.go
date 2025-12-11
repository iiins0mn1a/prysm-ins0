package sync

import (
	"context"
	"errors"
	"fmt"
	"time"

	fuzz "github.com/google/gofuzz"
	libp2ppeer "github.com/libp2p/go-libp2p/core/peer"
	"github.com/prysmaticlabs/prysm/v5/beacon-chain/p2p"
	p2ptypes "github.com/prysmaticlabs/prysm/v5/beacon-chain/p2p/types"
	cryptorand "github.com/prysmaticlabs/prysm/v5/crypto/rand"
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
	// Quick Return
}

// peerFuzzRoutine 是 PoS 中针对单个 peer 的基础 fuzzer 循环。
// 它会周期性地从该 peer 的历史请求中选取一些种子请求，进行轻量变异后重新发送。
func (s *Service) peerFuzzRoutine(ctx context.Context, id libp2ppeer.ID) {
	// 简单的频率控制：每 10ms 尝试一次。
	fmt.Printf("start Peer Fuzz Loop for peer %s\n", id.String())
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
			idx, err := randIndex(len(categories))
			if err != nil {
				continue
			}
			cat := categories[idx]

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

	if _, err := SendBeaconBlocksByRangeRequest(ctx, s.cfg.chain, s.cfg.p2p, id, orig, nil); err != nil {
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

	// 对原始请求进行扰动，制造不同的 root 组合。
	f.Fuzz(orig)

	if _, err := SendBeaconBlocksByRootRequest(ctx, s.cfg.clock, s.cfg.p2p, id, orig, nil); err != nil {
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
