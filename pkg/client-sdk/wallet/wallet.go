package wallet

import (
	"context"

	"github.com/ark-network/ark/pkg/client-sdk/explorer"
)

const (
	SingleKeyWallet = "singlekey"
)

type DescriptorAddress struct {
	Descriptor string
	Address    string
}

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
	) (offchainAddresses, boardingAddresses, redemptionAddresses []DescriptorAddress, err error)
	NewAddress(
		ctx context.Context, change bool,
	) (offchainAddr, onchainAddr *DescriptorAddress, err error)
	NewAddresses(
		ctx context.Context, change bool, num int,
	) (offchainAddresses, onchainAddresses []DescriptorAddress, err error)
	SignTransaction(
		ctx context.Context, explorerSvc explorer.Explorer, tx string,
	) (signedTx string, err error)
	SignMessage(
		ctx context.Context, message []byte, pubkey string,
	) (signature string, err error)
	Dump(ctx context.Context) (seed string, err error)
}
