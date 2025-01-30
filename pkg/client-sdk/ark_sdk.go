package arksdk

import (
	"context"

	"github.com/ark-network/ark/pkg/client-sdk/client"
	"github.com/ark-network/ark/pkg/client-sdk/types"
)

type Option func(options interface{}) error

type ArkClient interface {
	GetConfigData(ctx context.Context) (*types.Config, error)
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
		withZeroFees bool,
	) (string, error)
	UnilateralRedeem(ctx context.Context) error
	CollaborativeRedeem(
		ctx context.Context, addr string, amount uint64, withExpiryCoinselect bool,
		opts ...Option,
	) (string, error)
	Settle(ctx context.Context, opts ...Option) (string, error)
	ListVtxos(ctx context.Context) (spendable, spent []client.Vtxo, err error)
	Dump(ctx context.Context) (seed string, err error)
	GetTransactionHistory(ctx context.Context) ([]types.Transaction, error)
	GetTransactionEventChannel() chan types.TransactionEvent
	RedeemNotes(ctx context.Context, notes []string, opts ...Option) (string, error)
	SetNostrNotificationRecipient(ctx context.Context, nostrRecipient string) error
	SignTransaction(ctx context.Context, tx string) (string, error)
	Stop() error
}

type Receiver interface {
	To() string
	Amount() uint64

	IsOnchain() bool
}
