package btcwallet

import (
	"context"
	"time"

	"github.com/ark-network/ark/internal/core/ports"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type service struct {
	walletLoader *wallet.Loader
}

type WalletConfig struct {
	Datadir         string
	PublicPassword  []byte
	PrivatePassword []byte
	ChainParams     *chaincfg.Params
}

func New(cfg WalletConfig) (ports.WalletService, error) {
	loader := wallet.NewLoader(cfg.ChainParams, cfg.Datadir, true, 1*time.Minute, 512)
	exist, err := loader.WalletExists()
	if err != nil {
		return nil, err
	}

	if !exist {
		if _, err := loader.CreateNewWallet(cfg.PublicPassword, cfg.PrivatePassword, nil, time.Now()); err != nil {
			return nil, err
		}
	} else {
		if _, err := loader.OpenExistingWallet(cfg.PublicPassword, true); err != nil {
			return nil, err
		}
	}

	return &service{loader}, nil
}

// BroadcastTransaction implements ports.WalletService.
func (s *service) BroadcastTransaction(ctx context.Context, txHex string) (string, error) {
	panic("unimplemented")
}

// Close implements ports.WalletService.
func (s *service) Close() {
	panic("unimplemented")
}

// ConnectorsAccountBalance implements ports.WalletService.
func (s *service) ConnectorsAccountBalance(ctx context.Context) (uint64, uint64, error) {
	panic("unimplemented")
}

// DeriveAddresses implements ports.WalletService.
func (s *service) DeriveAddresses(ctx context.Context, num int) ([]string, error) {
	panic("unimplemented")
}

// DeriveConnectorAddress implements ports.WalletService.
func (s *service) DeriveConnectorAddress(ctx context.Context) (string, error) {
	panic("unimplemented")
}

// EstimateFees implements ports.WalletService.
func (s *service) EstimateFees(ctx context.Context, pset string) (uint64, error) {
	panic("unimplemented")
}

// GetNotificationChannel implements ports.WalletService.
func (s *service) GetNotificationChannel(ctx context.Context) <-chan map[string]ports.VtxoWithValue {
	panic("unimplemented")
}

// GetPubkey implements ports.WalletService.
func (s *service) GetPubkey(ctx context.Context) (*secp256k1.PublicKey, error) {
	panic("unimplemented")
}

// IsTransactionConfirmed implements ports.WalletService.
func (s *service) IsTransactionConfirmed(ctx context.Context, txid string) (isConfirmed bool, blocktime int64, err error) {
	panic("unimplemented")
}

// ListConnectorUtxos implements ports.WalletService.
func (s *service) ListConnectorUtxos(ctx context.Context, connectorAddress string) ([]ports.TxInput, error) {
	panic("unimplemented")
}

// LockConnectorUtxos implements ports.WalletService.
func (s *service) LockConnectorUtxos(ctx context.Context, utxos []ports.TxOutpoint) error {
	panic("unimplemented")
}

// MainAccountBalance implements ports.WalletService.
func (s *service) MainAccountBalance(ctx context.Context) (uint64, uint64, error) {
	panic("unimplemented")
}

// SelectUtxos implements ports.WalletService.
func (s *service) SelectUtxos(ctx context.Context, asset string, amount uint64) ([]ports.TxInput, uint64, error) {
	panic("unimplemented")
}

// SignPset implements ports.WalletService.
func (s *service) SignPset(ctx context.Context, pset string, extractRawTx bool) (string, error) {
	panic("unimplemented")
}

// SignPsetWithKey implements ports.WalletService.
func (s *service) SignPsetWithKey(ctx context.Context, pset string, inputIndexes []int) (string, error) {
	panic("unimplemented")
}

// Status implements ports.WalletService.
func (s *service) Status(ctx context.Context) (ports.WalletStatus, error) {
	panic("unimplemented")
}

// WaitForSync implements ports.WalletService.
func (s *service) WaitForSync(ctx context.Context, txid string) error {
	panic("unimplemented")
}

// WatchScripts implements ports.WalletService.
func (s *service) WatchScripts(ctx context.Context, scripts []string) error {
	panic("unimplemented")
}

// UnwatchScripts implements ports.WalletService.
func (s *service) UnwatchScripts(ctx context.Context, scripts []string) error {
	panic("unimplemented")
}
