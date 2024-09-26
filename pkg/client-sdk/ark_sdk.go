package arksdk

import (
	"context"

	"github.com/ark-network/ark/pkg/client-sdk/client"
	"github.com/ark-network/ark/pkg/client-sdk/store/domain"
)

type ArkClient interface {
	GetConfigData(ctx context.Context) (*domain.ConfigData, error)
	Init(ctx context.Context, args InitArgs) error
	InitWithWallet(ctx context.Context, args InitWithWalletArgs) error
	IsLocked(ctx context.Context) bool
	Unlock(ctx context.Context, password string) error
	Lock(ctx context.Context, password string) error
	Balance(ctx context.Context, computeExpiryDetails bool) (*Balance, error)
	Receive(ctx context.Context) (offchainAddr, boardingAddr string, err error)
	SendOnChain(ctx context.Context, receivers []Receiver) (string, error)
	SendOffChain(
		ctx context.Context, withExpiryCoinselect bool, receivers []Receiver,
	) (string, error)
	UnilateralRedeem(ctx context.Context) error
	CollaborativeRedeem(
		ctx context.Context, addr string, amount uint64, withExpiryCoinselect bool,
	) (string, error)
	SendAsync(ctx context.Context, withExpiryCoinselect bool, receivers []Receiver) (string, error)
	Claim(ctx context.Context) (string, error)
	ListVtxos(ctx context.Context) (spendable, spent []client.Vtxo, err error)
	Dump(ctx context.Context) (seed string, err error)
	GetTransactionHistory(ctx context.Context) ([]domain.Transaction, error)
	GetTransactionEventChannel() chan domain.Transaction
	Close() error
	ListenToVtxoChan() error
}

type Receiver interface {
	To() string
	Amount() uint64

	IsOnchain() bool
}
