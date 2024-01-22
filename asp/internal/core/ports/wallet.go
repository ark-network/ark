package ports

import (
	"context"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type WalletService interface {
	Status(ctx context.Context) (WalletStatus, error)
	GetPubkey(ctx context.Context) (*secp256k1.PublicKey, error)
	DeriveAddresses(ctx context.Context, num int) ([]string, error)
	SignPset(
		ctx context.Context, pset string, extractRawTx bool,
	) (string, error)
	SelectUtxos(ctx context.Context, asset string, amount uint64) ([]TxInput, uint64, error)
	BroadcastTransaction(ctx context.Context, txHex string) (string, error)
	Close()
}

type WalletStatus interface {
	IsInitialized() bool
	IsUnlocked() bool
	IsSynced() bool
}

type TxInput interface {
	GetTxid() string
	GetIndex() uint32
}
