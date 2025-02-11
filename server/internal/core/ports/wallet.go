package ports

import (
	"context"
	"errors"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
)

var (
	// ErrNonFinalBIP68 is returned when a transaction spending a CSV-locked output is not final.
	ErrNonFinalBIP68 = errors.New("non-final BIP68 sequence")
)

type WalletService interface {
	BlockchainScanner
	GetSyncedUpdate(ctx context.Context) <-chan struct{}
	GenSeed(ctx context.Context) (string, error)
	Create(ctx context.Context, seed, password string) error
	Restore(ctx context.Context, seed, password string) error
	Unlock(ctx context.Context, password string) error
	Lock(ctx context.Context, password string) error
	Status(ctx context.Context) (WalletStatus, error)
	GetPubkey(ctx context.Context) (*secp256k1.PublicKey, error)
	GetForfeitAddress(ctx context.Context) (string, error)
	DeriveConnectorAddress(ctx context.Context) (string, error)
	DeriveAddresses(ctx context.Context, num int) ([]string, error)
	SignTransaction(
		ctx context.Context, partialTx string, extractRawTx bool,
	) (string, error)
	SignTransactionTapscript(ctx context.Context, partialTx string, inputIndexes []int) (string, error) // inputIndexes == nil means sign all inputs
	SelectUtxos(ctx context.Context, asset string, amount uint64) ([]TxInput, uint64, error)
	BroadcastTransaction(ctx context.Context, txHex string) (string, error)
	WaitForSync(ctx context.Context, txid string) error
	EstimateFees(ctx context.Context, psbt string) (uint64, error)
	MinRelayFee(ctx context.Context, vbytes uint64) (uint64, error)
	MinRelayFeeRate(ctx context.Context) chainfee.SatPerKVByte
	ListConnectorUtxos(ctx context.Context, connectorAddress string) ([]TxInput, error)
	MainAccountBalance(ctx context.Context) (uint64, uint64, error)
	ConnectorsAccountBalance(ctx context.Context) (uint64, uint64, error)
	LockConnectorUtxos(ctx context.Context, utxos []TxOutpoint) error
	GetDustAmount(ctx context.Context) (uint64, error)
	GetTransaction(ctx context.Context, txid string) (string, error)
	SignMessage(ctx context.Context, message []byte) ([]byte, error)
	VerifyMessageSignature(ctx context.Context, message, signature []byte) (bool, error)
	GetCurrentBlockTime(ctx context.Context) (*BlockTimestamp, error)
	Withdraw(ctx context.Context, address string, amount uint64) (string, error)
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

type BlockTimestamp struct {
	Height uint32
	Time   int64
}
