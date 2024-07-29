package wallet

import (
	"context"

	"github.com/ark-network/ark-sdk/explorer"
)

const (
	SingleKeyWallet = "singlekey"
)

type Wallet interface {
	GetType() string
	Create(
		ctx context.Context, password, seed string,
	) (walletSeed string, err error)
	Lock(ctx context.Context, password string) (err error)
	Unlock(ctx context.Context, password string) (alreadyUnlocked bool, err error)
	IsLocked() bool
	GetAddresses(
		ctx context.Context,
	) (offchainAddresses, onchainAddresses, redemptionAddresses []string, err error)
	NewAddress(
		ctx context.Context, change bool,
	) (offchainAddr, onchainAddr string, err error)
	NewAddresses(
		ctx context.Context, change bool, num int,
	) (offchainAddresses, onchainAddresses []string, err error)
	SignTransaction(
		ctx context.Context, explorerSvc explorer.Explorer, tx string,
	) (singedTx string, err error)
}
