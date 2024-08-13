package arksdk

import (
	"context"

	"github.com/ark-network/ark/pkg/client-sdk/store"
)

type ArkClient interface {
	GetConfigData(ctx context.Context) (*store.StoreData, error)
	Init(ctx context.Context, args InitArgs) error
	InitWithWallet(ctx context.Context, args InitWithWalletArgs) error
	IsLocked(ctx context.Context) bool
	Unlock(ctx context.Context, password string) error
	Lock(ctx context.Context, password string) error
	Balance(ctx context.Context, computeExpiryDetails bool) (*Balance, error)
	Onboard(ctx context.Context, amount uint64) (string, error)
	Receive(ctx context.Context) (string, string, error)
	SendOnChain(ctx context.Context, receivers []Receiver) (string, error)
	SendOffChain(
		ctx context.Context, withExpiryCoinselect bool, receivers []Receiver,
	) (string, error)
	UnilateralRedeem(ctx context.Context) error
	CollaborativeRedeem(
		ctx context.Context, addr string, amount uint64, withExpiryCoinselect bool,
	) (string, error)
	SendAsync(ctx context.Context, withExpiryCoinselect bool, receivers []Receiver) (string, error)
	ClaimAsync(ctx context.Context) (string, error)
}

type Receiver interface {
	To() string
	Amount() uint64

	isOnchain() bool
}
