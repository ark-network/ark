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
	Transfer(ctx context.Context, outs []TxOutput) (string, error)
	BroadcastTransaction(ctx context.Context, txHex string) (string, error)
	SignPsetWithKey(ctx context.Context, pset string, inputIndex int) (string, error)
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
	GetScript() string
	GetScriptSigSize() int
	GetWitnessSize() int
}

type TxOutput interface {
	GetAmount() uint64
	GetAsset() string
	GetScript() string
}
