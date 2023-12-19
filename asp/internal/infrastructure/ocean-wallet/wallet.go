package oceanwallet

import (
	"context"
	"fmt"

	pb "github.com/ark-network/ark/api-spec/protobuf/gen/ocean/v1"
	"github.com/ark-network/ark/internal/core/ports"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/vulpemventures/go-bip32"
)

const accountLabel = "ark"

var derivationPath = []uint32{0, 0}

func (s *service) GetPubkey(ctx context.Context) (*secp256k1.PublicKey, error) {
	key, _, err := s.getPubkey(ctx)
	return key, err
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

func (s *service) getPubkey(ctx context.Context) (*secp256k1.PublicKey, *bip32.Key, error) {
	res, err := s.walletClient.GetInfo(ctx, &pb.GetInfoRequest{})
	if err != nil {
		return nil, nil, err
	}
	if len(res.GetAccounts()) <= 0 {
		return nil, nil, fmt.Errorf("wallet is locked")
	}
	xpub := res.GetAccounts()[0].GetXpubs()[0]
	node, err := hdkeychain.NewKeyFromString(xpub)
	if err != nil {
		return nil, nil, err
	}
	for _, i := range derivationPath {
		node, err = node.Derive(i)
		if err != nil {
			return nil, nil, err
		}
	}
	key, err := node.ECPubKey()

	if err != nil {
		return nil, nil, err
	}

	masterKey, err := bip32.B58Deserialize(xpub)
	if err != nil {
		return nil, nil, err
	}

	return key, masterKey, nil
}
