package ports

import (
	"context"
	"errors"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// ErrNonFinalBIP68 is returned when a transaction spending a CSV-locked output is not final.
var ErrNonFinalBIP68 = errors.New("non-final BIP68 sequence")

type WalletService interface {
	BlockchainScanner
	Status(ctx context.Context) (WalletStatus, error)
	GetPubkey(ctx context.Context) (*secp256k1.PublicKey, error)
	DeriveConnectorAddress(ctx context.Context) (string, error)
	DeriveAddresses(ctx context.Context, num int) ([]string, error)
	SignTransaction(
		ctx context.Context, partialTx string, extractRawTx bool,
	) (string, error)
	SignTransactionTapscript(ctx context.Context, pset string, inputIndexes []int) (string, error) // inputIndexes == nil means sign all inputs
	SelectUtxos(ctx context.Context, asset string, amount uint64) ([]TxInput, uint64, error)
	BroadcastTransaction(ctx context.Context, txHex string) (string, error)
	WaitForSync(ctx context.Context, txid string) error
	EstimateFees(ctx context.Context, psbt string) (uint64, error)
	ListConnectorUtxos(ctx context.Context, connectorAddress string) ([]TxInput, error)
	MainAccountBalance(ctx context.Context) (uint64, uint64, error)
	ConnectorsAccountBalance(ctx context.Context) (uint64, uint64, error)
	LockConnectorUtxos(ctx context.Context, utxos []TxOutpoint) error
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
	GetAsset() string
	GetValue() uint64
}

type TxOutpoint interface {
	GetTxid() string
	GetIndex() uint32
}
