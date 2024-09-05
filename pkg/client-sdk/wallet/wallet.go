package wallet

import (
	"context"

	"github.com/ark-network/ark/pkg/client-sdk/explorer"
)

const (
	SingleKeyWallet = "singlekey"
)

type WalletService interface {
	GetType() string
	Create(
		ctx context.Context, password, seed string,
	) (walletSeed string, err error)
	Lock(ctx context.Context, password string) (err error)
	Unlock(ctx context.Context, password string) (alreadyUnlocked bool, err error)
	IsLocked() bool
	GetAddresses(
		ctx context.Context,
	) (offchainAddresses, boardingAddresses, redemptionAddresses []string, err error)
	NewAddress(
		ctx context.Context, change bool,
	) (offchainAddr, onchainAddr string, err error)
	NewAddresses(
		ctx context.Context, change bool, num int,
	) (offchainAddresses, onchainAddresses []string, err error)
	SignTransaction(
		ctx context.Context, explorerSvc explorer.Explorer, tx string,
	) (signedTx string, err error)
}
