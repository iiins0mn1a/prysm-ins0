package p2p

import (
	"reflect"

	p2ptypes "github.com/prysmaticlabs/prysm/v5/beacon-chain/p2p/types"
	"github.com/prysmaticlabs/prysm/v5/consensus-types/primitives"
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
