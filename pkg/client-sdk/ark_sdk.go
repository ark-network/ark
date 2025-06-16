package arksdk

import (
	"context"

	"github.com/ark-network/ark/pkg/client-sdk/client"
	"github.com/ark-network/ark/pkg/client-sdk/types"
)

var Version string

type Option func(options interface{}) error

type ArkClient interface {
	GetVersion() string
	GetConfigData(ctx context.Context) (*types.Config, error)
	Init(ctx context.Context, args InitArgs) error
	InitWithWallet(ctx context.Context, args InitWithWalletArgs) error
	IsLocked(ctx context.Context) bool
	Unlock(ctx context.Context, password string) error
	Lock(ctx context.Context) error
	Balance(ctx context.Context, computeExpiryDetails bool) (*Balance, error)
	Receive(ctx context.Context) (onchainAddr, offchainAddr, boardingAddr string, err error)
	SendOffChain(
		ctx context.Context, withExpiryCoinselect bool, receivers []Receiver,
		withZeroFees bool,
	) (string, error)
	RegisterIntent(
		ctx context.Context,
		vtxos []client.Vtxo,
		boardingUtxos []types.Utxo,
		notes []string,
		outputs []client.Output,
		cosignersPublicKeys []string,
	) (intentID string, err error)
	DeleteIntent(
		ctx context.Context,
		vtxos []client.Vtxo,
		boardingUtxos []types.Utxo,
		notes []string,
	) error
	Settle(ctx context.Context, opts ...Option) (string, error)
	CollaborativeExit(
		ctx context.Context, addr string, amount uint64, withExpiryCoinselect bool,
		opts ...Option,
	) (string, error)
	StartUnilateralExit(ctx context.Context) error
	CompleteUnilateralExit(ctx context.Context, to string) (string, error)
	OnboardAgainAllExpiredBoardings(ctx context.Context) (string, error)
	WithdrawFromAllExpiredBoardings(ctx context.Context, to string) (string, error)
	ListVtxos(ctx context.Context) (spendable, spent []client.Vtxo, err error)
	Dump(ctx context.Context) (seed string, err error)
	GetTransactionHistory(ctx context.Context) ([]types.Transaction, error)
	GetTransactionEventChannel(ctx context.Context) chan types.TransactionEvent
	GetVtxoEventChannel(ctx context.Context) chan types.VtxoEvent
	RedeemNotes(ctx context.Context, notes []string, opts ...Option) (string, error)
	SignTransaction(ctx context.Context, tx string) (string, error)
	NotifyIncomingFunds(ctx context.Context, address string) ([]types.Vtxo, error)
	Reset(ctx context.Context)
	Stop()
}

type Receiver interface {
	To() string
	Amount() uint64

	IsOnchain() bool
}
