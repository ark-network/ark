package btcwallet

import (
	"context"
	"errors"
	"time"

	"github.com/ark-network/ark/internal/core/ports"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/sirupsen/logrus"
)

type accountName string

const (
	mainAccount      accountName = "main"
	connectorAccount accountName = "connector"
)

var keyScope = waddrmgr.KeyScopeBIP0044

type service struct {
	loader          *wallet.Loader
	publicPassword  []byte
	privatePassword []byte
	accounts        map[accountName]uint32
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

	accounts := make(map[accountName]uint32)

	if !exist {
		w, err := loader.CreateNewWallet(cfg.PublicPassword, cfg.PrivatePassword, nil, time.Now())
		if err != nil {
			return nil, err
		}

		mainAccountNumber, err := w.NextAccount(keyScope, string(mainAccount))
		if err != nil {
			return nil, err
		}

		connectorAccountNumber, err := w.NextAccount(keyScope, string(connectorAccount))
		if err != nil {
			return nil, err
		}

		accounts[mainAccount] = mainAccountNumber
		accounts[connectorAccount] = connectorAccountNumber
	} else {
		w, err := loader.OpenExistingWallet(cfg.PublicPassword, true)
		if err != nil {
			return nil, err
		}

		mainAccountNumber, err := w.AccountNumber(keyScope, string(mainAccount))
		if err != nil {
			return nil, err
		}

		connectorAccountNumber, err := w.AccountNumber(keyScope, string(connectorAccount))
		if err != nil {
			return nil, err
		}

		accounts[mainAccount] = mainAccountNumber
		accounts[connectorAccount] = connectorAccountNumber
	}

	return &service{loader, cfg.PublicPassword, cfg.PrivatePassword, accounts}, nil
}

func (s *service) Close() {
	if err := s.loader.UnloadWallet(); err != nil {
		logrus.Errorf("error while unloading wallet: %s", err)
	}
}

func (s *service) BroadcastTransaction(ctx context.Context, txHex string) (string, error) {
	panic("unimplemented")
}

func (s *service) ConnectorsAccountBalance(ctx context.Context) (uint64, uint64, error) {
	amount, err := s.getBalance(connectorAccount)
	if err != nil {
		return 0, 0, err
	}

	return amount, 0, nil
}

func (s *service) MainAccountBalance(ctx context.Context) (uint64, uint64, error) {
	amount, err := s.getBalance(mainAccount)
	if err != nil {
		return 0, 0, err
	}

	return amount, 0, nil
}

func (s *service) DeriveAddresses(ctx context.Context, num int) ([]string, error) {
	addresses := make([]string, 0, num)

	for i := 0; i < num; i++ {
		addr, err := s.deriveNextAddress(mainAccount)
		if err != nil {
			return nil, err
		}

		addresses = append(addresses, addr.EncodeAddress())
	}

	return addresses, nil
}

func (s *service) DeriveConnectorAddress(ctx context.Context) (string, error) {
	addr, err := s.deriveNextAddress(connectorAccount)
	if err != nil {
		return "", err
	}

	return addr.EncodeAddress(), nil
}

func (s *service) GetPubkey(ctx context.Context) (*secp256k1.PublicKey, error) {
	w, err := s.getWallet()
	if err != nil {
		return nil, err
	}

	addrs, err := w.AccountAddresses(s.accounts[mainAccount])
	if err != nil {
		return nil, err
	}

	var firstAddr btcutil.Address

	if len(addrs) == 0 {
		addr, err := w.NewAddress(s.accounts[mainAccount], keyScope)
		if err != nil {
			return nil, err
		}

		firstAddr = addr
	} else {
		firstAddr = addrs[0]
	}

	pubKey, err := w.PubKeyForAddress(firstAddr)
	if err != nil {
		return nil, err
	}

	return pubKey, nil
}

// ListConnectorUtxos implements ports.WalletService.
func (s *service) ListConnectorUtxos(ctx context.Context, connectorAddress string) ([]ports.TxInput, error) {
	panic("unimplemented")
}

// LockConnectorUtxos implements ports.WalletService.
func (s *service) LockConnectorUtxos(ctx context.Context, utxos []ports.TxOutpoint) error {
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

func (s *service) EstimateFees(ctx context.Context, pset string) (uint64, error) {
	panic("unimplemented")
}

// GetNotificationChannel implements ports.WalletService.
func (s *service) GetNotificationChannel(ctx context.Context) <-chan map[string]ports.VtxoWithValue {
	panic("unimplemented")
}

func (s *service) IsTransactionConfirmed(ctx context.Context, txid string) (isConfirmed bool, blocktime int64, err error) {
	panic("unimplemented")
}

func (s *service) getWallet() (*wallet.Wallet, error) {
	w, isLoaded := s.loader.LoadedWallet()
	if !isLoaded {
		return nil, errors.New("wallet is not loaded")
	}

	return w, nil
}

func (s *service) getBalance(account accountName) (uint64, error) {
	w, err := s.getWallet()
	if err != nil {
		return 0, err
	}

	accountsBalances, err := w.AccountBalances(keyScope, 0)
	if err != nil {
		return 0, err
	}

	for _, balance := range accountsBalances {
		if balance.AccountName == string(account) {
			return uint64(balance.AccountBalance.ToUnit(btcutil.AmountSatoshi)), nil
		}
	}

	return 0, errors.New("account not found")
}

func (s *service) deriveNextAddress(account accountName) (btcutil.Address, error) {
	w, err := s.getWallet()
	if err != nil {
		return nil, err
	}

	return w.NewAddress(s.accounts[account], keyScope)
}
