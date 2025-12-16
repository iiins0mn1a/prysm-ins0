package p2p

import (
	"fmt"
	"reflect"

	"github.com/libp2p/go-libp2p/core/peer"
	ssz "github.com/prysmaticlabs/fastssz"
	p2ptypes "github.com/prysmaticlabs/prysm/v5/beacon-chain/p2p/types"
	"github.com/prysmaticlabs/prysm/v5/consensus-types/primitives"
	cryptorand "github.com/prysmaticlabs/prysm/v5/crypto/rand"
	ethpb "github.com/prysmaticlabs/prysm/v5/proto/prysm/v1alpha1"
	pb "github.com/prysmaticlabs/prysm/v5/proto/prysm/v1alpha1"
)

// classifyRPC maps an RPC base topic and message value to a logical
// category name aligned with the groupings in LOKI-POS.md. If the
// combination is not recognised, it returns an empty string.
func classifyRPC(baseTopic string, msg interface{}) string {
	switch baseTopic {
	case RPCStatusTopicV1:
		if _, ok := msg.(*pb.Status); ok {
			return "ConsensusStatusMsgs"
		}
	case RPCGoodByeTopicV1:
		if _, ok := msg.(primitives.SSZUint64); ok {
			return "ConsensusGoodbyeMsgs"
		}
	case RPCPingTopicV1:
		if _, ok := msg.(primitives.SSZUint64); ok {
			return "ConsensusPingMsgs"
		}
	case RPCBlocksByRangeTopicV1, RPCBlocksByRangeTopicV2:
		if _, ok := msg.(*pb.BeaconBlocksByRangeRequest); ok {
			return "BeaconBlocksByRangeReqMsgs"
		}
	case RPCBlocksByRootTopicV1, RPCBlocksByRootTopicV2:
		if _, ok := msg.(*p2ptypes.BeaconBlockByRootsReq); ok {
			return "BeaconBlocksByRootReqMsgs"
		}
	case RPCMetaDataTopicV1:
		// Metadata V1 does not carry a concrete type in this mapping,
		// so we only check that it is non-nil.
		if msg != nil {
			return "MetadataV1ReqMsgs"
		}
	case RPCMetaDataTopicV2:
		if msg != nil {
			return "MetadataV2ReqMsgs"
		}
	case RPCBlobSidecarsByRangeTopicV1:
		if _, ok := msg.(*pb.BlobSidecarsByRangeRequest); ok {
			return "BlobSidecarsByRangeReqMsgs"
		}
	case RPCBlobSidecarsByRootTopicV1:
		if _, ok := msg.(*p2ptypes.BlobSidecarsByRootReq); ok {
			return "BlobSidecarsByRootReqMsgs"
		}
	}

	// Fallback: try to infer from the concrete type if we missed a topic
	// variant, without enforcing it for correctness.
	switch reflect.TypeOf(msg) {
	case reflect.TypeOf(&pb.Status{}):
		return "ConsensusStatusMsgs"
	case reflect.TypeOf(primitives.SSZUint64(0)):
		// Could be ping or goodbye; leave empty to avoid ambiguity.
		return ""
	case reflect.TypeOf(&pb.BeaconBlocksByRangeRequest{}):
		return "BeaconBlocksByRangeReqMsgs"
	case reflect.TypeOf(&p2ptypes.BeaconBlockByRootsReq{}):
		return "BeaconBlocksByRootReqMsgs"
	case reflect.TypeOf(&pb.BlobSidecarsByRangeRequest{}):
		return "BlobSidecarsByRangeReqMsgs"
	case reflect.TypeOf(&p2ptypes.BlobSidecarsByRootReq{}):
		return "BlobSidecarsByRootReqMsgs"
	default:
		return ""
	}
}

// classifyGossipCategory maps a gossip object to a logical category name
// aligned with the groupings in LOKI-POS.md. It operates on the concrete
// SSZ-marshaler type.
func classifyGossipCategory(obj ssz.Marshaler) string {
	switch v := obj.(type) {
	// Blocks by fork
	case *ethpb.SignedBeaconBlock:
		return "BeaconBlocksMsgsPhase0"
	case *ethpb.SignedBeaconBlockAltair:
		return "BeaconBlocksAltairMsgs"
	case *ethpb.SignedBeaconBlockBellatrix:
		return "BeaconBlocksBellatrixMsgs"
	case *ethpb.SignedBeaconBlockCapella:
		return "BeaconBlocksCapellaMsgs"
	case *ethpb.SignedBeaconBlockDeneb:
		return "BeaconBlocksDenebMsgs"
	case *ethpb.SignedBeaconBlockElectra:
		return "BeaconBlocksElectraMsgs"

	// Attestations
	case *ethpb.AttestationElectra:
		return "AttestationsElectraMsgs"
	case *ethpb.Attestation:
		return "AttestationsMsgs"

	// Aggregate attestations
	case *ethpb.SignedAggregateAttestationAndProofElectra:
		return "AggregateAndProofElectraMsgs"
	case *ethpb.SignedAggregateAttestationAndProof:
		return "AggregateAndProofMsgs"

	// Slashings & exits
	case *ethpb.AttesterSlashingElectra:
		return "AttesterSlashingElectraMsgs"
	case *ethpb.AttesterSlashing:
		return "AttesterSlashingMsgs"
	case *ethpb.ProposerSlashing:
		return "ProposerSlashingMsgs"
	case *ethpb.SignedVoluntaryExit:
		return "VoluntaryExitMsgs"

	// Sync committee
	case *ethpb.SyncCommitteeMessage:
		return "SyncCommitteeMsgs"
	case *ethpb.SignedContributionAndProof:
		return "SyncContributionAndProofMsgs"

	// Other
	case *ethpb.SignedBLSToExecutionChange:
		return "BLSToExecutionChangeMsgs"
	case *ethpb.BlobSidecar:
		return "BlobSidecarMsgs"
	default:
		// As a safety net, inspect the reflected type in case we are
		// dealing with aliases or wrapped types.
		switch reflect.TypeOf(v) {
		case reflect.TypeOf(&ethpb.BlobSidecar{}):
			return "BlobSidecarMsgs"
		default:
			fmt.Println("Unknown gossip category", reflect.TypeOf(v))
			return ""
		}
	}
}

// SelectRandomCategory 从记录的消息中随机选择一个有可用种子的 category。
// 包括所有 RPC 和 Gossip 相关的 categories。
func SelectRandomCategory(recs []RecordedMessage) string {
	// 收集所有可用的 category（RPC + Gossip）
	availableCategories := []string{
		// RPC categories
		"ConsensusStatusMsgs",
		"ConsensusGoodbyeMsgs",
		"ConsensusPingMsgs",
		"BeaconBlocksByRangeReqMsgs",
		"BeaconBlocksByRootReqMsgs",
		"MetadataV1ReqMsgs",
		"MetadataV2ReqMsgs",
		"BlobSidecarsByRangeReqMsgs",
		"BlobSidecarsByRootReqMsgs",
		// Gossip categories - Blocks by fork
		"BeaconBlocksMsgsPhase0",
		"BeaconBlocksAltairMsgs",
		"BeaconBlocksBellatrixMsgs",
		"BeaconBlocksCapellaMsgs",
		"BeaconBlocksDenebMsgs",
		"BeaconBlocksElectraMsgs",
		// Gossip categories - Attestations
		"AttestationsElectraMsgs",
		"AttestationsMsgs",
		// Gossip categories - Aggregate attestations
		"AggregateAndProofElectraMsgs",
		"AggregateAndProofMsgs",
		// Gossip categories - Slashings & exits
		"AttesterSlashingElectraMsgs",
		"AttesterSlashingMsgs",
		"ProposerSlashingMsgs",
		"VoluntaryExitMsgs",
		// Gossip categories - Sync committee
		"SyncCommitteeMsgs",
		"SyncContributionAndProofMsgs",
		// Gossip categories - Other
		"BLSToExecutionChangeMsgs",
		"BlobSidecarMsgs",
	}

	// 过滤出有可用种子的 category
	validCategories := make([]string, 0)
	for _, cat := range availableCategories {
		for _, r := range recs {
			if r.Category == cat {
				validCategories = append(validCategories, cat)
				break
			}
		}
	}

	if len(validCategories) == 0 {
		return ""
	}

	// 使用 crypto-secure random 选择
	randGen := cryptorand.NewDeterministicGenerator()
	idx := randGen.Intn(len(validCategories))
	return validCategories[idx]
}

// recordGossipForPeers records a gossip message for a (possibly approximate)
// set of peers using the shared fuzz recorder. The category should match
// the logical groupings defined in LOKI-POS.md.
func (s *Service) recordGossipForPeers(category string, msg interface{}, peers []peer.ID, topic string) {
	if s.fuzzRecorder == nil || category == "" || len(peers) == 0 {
		return
	}
	for _, pid := range peers {
		s.fuzzRecorder.RecordOutgoing(pid, category, topic, msg)
	}
}
