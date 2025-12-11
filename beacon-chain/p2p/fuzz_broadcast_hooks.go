package p2p

import (
	"fmt"
	"reflect"

	"github.com/libp2p/go-libp2p/core/peer"
	ssz "github.com/prysmaticlabs/fastssz"
	ethpb "github.com/prysmaticlabs/prysm/v5/proto/prysm/v1alpha1"
)

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
