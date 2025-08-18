package stateutil

import (
	fieldparams "github.com/OffchainLabs/prysm/v6/config/fieldparams"
	"github.com/OffchainLabs/prysm/v6/encoding/ssz"
	ethpb "github.com/OffchainLabs/prysm/v6/proto/prysm/v1alpha1"
)

// BuilderPendingWithdrawalsRoot computes the SSZ root of a slice of BuilderPendingWithdrawal.
func BuilderPendingWithdrawalsRoot(slice []*ethpb.BuilderPendingWithdrawal) ([32]byte, error) {
	return ssz.SliceRoot(slice, fieldparams.BuilderPendingWithdrawalsLimit)
}
