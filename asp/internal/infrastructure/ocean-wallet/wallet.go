package oceanwallet

import (
	"context"
	"fmt"

	pb "github.com/ark-network/ark/api-spec/protobuf/gen/ocean/v1"
	"github.com/ark-network/ark/internal/core/ports"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

const accountLabel = "ark"

func (s *service) GetPubkey(ctx context.Context) (*secp256k1.PublicKey, error) {
	res, err := s.walletClient.GetInfo(ctx, &pb.GetInfoRequest{})
	if err != nil {
		return nil, err
	}
	if len(res.GetAccounts()) <= 0 {
		return nil, fmt.Errorf("wallet is locked")
	}
	xpub := res.GetAccounts()[0].GetXpubs()[0]
	node, err := hdkeychain.NewKeyFromString(xpub)
	if err != nil {
		return nil, err
	}
	for i := 0; i < 2; i++ {
		node, err = node.Derive(0)
		if err != nil {
			return nil, err
		}
	}
	return node.ECPubKey()
}

func (s *service) Status(
	ctx context.Context,
) (ports.WalletStatus, error) {
	res, err := s.walletClient.Status(ctx, &pb.StatusRequest{})
	if err != nil {
		return nil, err
	}
	return walletStatus{res}, nil
}

type walletStatus struct {
	*pb.StatusResponse
}

func (w walletStatus) IsInitialized() bool {
	return w.StatusResponse.GetInitialized()
}
func (w walletStatus) IsUnlocked() bool {
	return w.StatusResponse.GetUnlocked()
}
func (w walletStatus) IsSynced() bool {
	return w.StatusResponse.GetSynced()
}
