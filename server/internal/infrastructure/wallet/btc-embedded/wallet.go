package btcwallet

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/internal/core/domain"
	"github.com/ark-network/ark/internal/core/ports"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btclog"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/btcsuite/btcwallet/walletdb"
	_ "github.com/btcsuite/btcwallet/walletdb/bdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/lightninglabs/neutrino"
	"github.com/sirupsen/logrus"
)

type WalletOption func(*service) error

type WalletConfig struct {
	Datadir         string
	PublicPassword  []byte
	PrivatePassword []byte
	Network         common.Network
	EsploraURL      string
}

type accountName string

const (
	mainAccount      accountName = "main"
	connectorAccount accountName = "connector"
	aspKeyAccount    accountName = "aspkey"
)

var (
	keyScope           = waddrmgr.KeyScopeBIP0084
	keyScopeASPKey     = waddrmgr.KeyScopeBIP0086
	outputLockDuration = time.Minute
)

type service struct {
	loader   *wallet.Loader
	accounts map[accountName]uint32
	cfg      WalletConfig

	chainSource chain.Interface

	esploraClient *esploraClient

	watchedScriptsLock sync.Mutex
	watchedScripts     map[string]struct{}

	aspKey *secp256k1.PublicKey
}

func WithChainSource(chainSource chain.Interface) WalletOption {
	return func(s *service) error {
		if s.chainSource != nil {
			return errors.New("chain source already set")
		}

		s.chainSource = chainSource
		return nil
	}
}

// WithNeutrino creates a start a neutrino node using the provided service datadir
func WithNeutrino(initialPeer string) WalletOption {
	return func(s *service) error {
		if s.cfg.Network.Name == common.BitcoinRegTest.Name && len(initialPeer) == 0 {
			return errors.New("initial neutrino peer required for regtest network, set NEUTRINO_PEER env var")
		}

		db, err := walletdb.Create(
			"bdb", s.cfg.Datadir+"/neutrino.db", true, 60*time.Second,
		)
		if err != nil {
			return err
		}

		netParams := s.chainParams()

		config := neutrino.Config{
			DataDir:     s.cfg.Datadir,
			ChainParams: *netParams,
			Database:    db,
		}

		if len(initialPeer) > 0 {
			config.AddPeers = []string{initialPeer}
		}

		neutrino.UseLogger(logger("neutrino"))

		neutrinoSvc, err := neutrino.NewChainService(config)
		if err != nil {
			return err
		}

		if err := neutrinoSvc.Start(); err != nil {
			return err
		}

		// wait for neutrino to sync
		for !neutrinoSvc.IsCurrent() {
			time.Sleep(1 * time.Second)
		}

		chainSrc := chain.NewNeutrinoClient(netParams, neutrinoSvc)
		if err := chainSrc.Start(); err != nil {
			return err
		}

		return WithChainSource(chainSrc)(s)
	}
}

// NewService creates the wallet service, an option must be set to configure the chain source.
func NewService(cfg WalletConfig, options ...WalletOption) (ports.WalletService, error) {
	wallet.UseLogger(logger("wallet"))

	svc := &service{
		loader:             nil,
		accounts:           make(map[accountName]uint32),
		cfg:                cfg,
		esploraClient:      &esploraClient{url: cfg.EsploraURL},
		watchedScriptsLock: sync.Mutex{},
		watchedScripts:     make(map[string]struct{}),
	}

	for _, option := range options {
		option(svc)
	}

	if svc.chainSource == nil {
		return nil, errors.New("chain source not provided, please use WalletOption to set it")
	}

	if err := svc.setWalletLoader(); err != nil {
		return nil, err
	}

	// verify that the wallet has been correctly loaded
	_, isLoaded := svc.loader.LoadedWallet()
	if !isLoaded {
		return nil, errors.New("wallet not loaded")
	}

	return svc, nil
}

// setWalletLoader init the wallet db and configure the wallet accounts
func (s *service) setWalletLoader() error {
	loader := wallet.NewLoader(s.chainParams(), s.cfg.Datadir, true, 1*time.Minute, 512)
	exist, err := loader.WalletExists()
	if err != nil {
		return err
	}

	accounts := make(map[accountName]uint32)

	if !exist {
		logrus.Info("wallet does not exist, creating new wallet")
		w, err := loader.CreateNewWallet(s.cfg.PublicPassword, s.cfg.PrivatePassword, nil, time.Now())
		if err != nil {
			return err
		}

		if err := w.Unlock(s.cfg.PrivatePassword, nil); err != nil {
			return err
		}
		defer w.Lock()

		mainAccountNumber, err := w.NextAccount(keyScope, string(mainAccount))
		if err != nil {
			return err
		}

		connectorAccountNumber, err := w.NextAccount(keyScope, string(connectorAccount))
		if err != nil {
			return err
		}

		aspKeyAccountNumber, err := w.NextAccount(keyScopeASPKey, string(aspKeyAccount))
		if err != nil {
			return err
		}

		accounts[mainAccount] = mainAccountNumber
		accounts[connectorAccount] = connectorAccountNumber
		accounts[aspKeyAccount] = aspKeyAccountNumber
	} else {
		logrus.Info("wallet exists, opening wallet")
		w, err := loader.OpenExistingWallet(s.cfg.PublicPassword, true)
		if err != nil {
			return err
		}

		if err := w.Unlock(s.cfg.PrivatePassword, nil); err != nil {
			return err
		}
		defer w.Lock()

		var mainAccountNumber, connectorAccountNumber, aspKeyAccountNumber uint32

		mainAccountNumber, err = w.AccountNumber(keyScope, string(mainAccount))
		if err != nil {
			if mgrErr := err.(waddrmgr.ManagerError); mgrErr.ErrorCode == waddrmgr.ErrAccountNotFound {
				mainAccountNumber, err = w.NextAccount(keyScope, string(mainAccount))
				if err != nil {
					return err
				}
			} else {
				return err
			}
		}

		connectorAccountNumber, err = w.AccountNumber(keyScope, string(connectorAccount))
		if err != nil {
			if mgrErr := err.(waddrmgr.ManagerError); mgrErr.ErrorCode == waddrmgr.ErrAccountNotFound {
				connectorAccountNumber, err = w.NextAccount(keyScope, string(connectorAccount))
				if err != nil {
					return err
				}
			} else {
				return err
			}
		}

		aspKeyAccountNumber, err = w.AccountNumber(keyScopeASPKey, string(aspKeyAccount))
		if err != nil {
			if mgrErr := err.(waddrmgr.ManagerError); mgrErr.ErrorCode == waddrmgr.ErrAccountNotFound {
				aspKeyAccountNumber, err = w.NextAccount(keyScopeASPKey, string(aspKeyAccount))
				if err != nil {
					return err
				}
			} else {
				return err
			}
		}

		accounts[mainAccount] = mainAccountNumber
		accounts[connectorAccount] = connectorAccountNumber
		accounts[aspKeyAccount] = aspKeyAccountNumber
	}

	// generate the main ASP key

	w, _ := loader.LoadedWallet()
	w.SynchronizeRPC(s.chainSource)

	addrs, err := w.AccountAddresses(accounts[aspKeyAccount])
	if err != nil {
		return err
	}

	if len(addrs) == 0 {
		addr, err := w.NewAddress(accounts[aspKeyAccount], keyScopeASPKey)
		if err != nil {
			return err
		}

		pubKey, err := w.PubKeyForAddress(addr)
		if err != nil {
			return err
		}

		s.aspKey = pubKey
	} else {
		pubKey, err := w.PubKeyForAddress(addrs[0])
		if err != nil {
			return err
		}

		s.aspKey = pubKey
	}

	s.loader = loader
	s.accounts = accounts

	return nil
}

func (s *service) Close() {
	if err := s.loader.UnloadWallet(); err != nil {
		logrus.Errorf("error while unloading wallet: %s", err)
	}

	s.chainSource.Stop()
}

func (s *service) BroadcastTransaction(ctx context.Context, txHex string) (string, error) {
	var tx wire.MsgTx
	if err := tx.Deserialize(hex.NewDecoder(strings.NewReader(txHex))); err != nil {
		return "", err
	}

	// TODO min-relay-fee not met errors are not handled (important)

	w, _ := s.loader.LoadedWallet()

	if err := w.PublishTransaction(&tx, ""); err != nil {
		return "", err
	}

	return tx.TxHash().String(), nil
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

	if len(addresses) == 0 {
		return nil, errors.New("no addresses derived")
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
	return s.aspKey, nil
}

func (s *service) ListConnectorUtxos(ctx context.Context, connectorAddress string) ([]ports.TxInput, error) {
	w, _ := s.loader.LoadedWallet()

	addr, err := btcutil.DecodeAddress(connectorAddress, w.ChainParams())
	if err != nil {
		return nil, err
	}

	script, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return nil, err
	}

	utxos, err := w.UnspentOutputs(wallet.OutputSelectionPolicy{
		Account:               s.accounts[connectorAccount],
		RequiredConfirmations: 0,
	})
	if err != nil {
		return nil, err
	}

	txInputs := make([]ports.TxInput, 0, len(utxos))
	for _, utxo := range utxos {
		if !bytes.Equal(utxo.Output.PkScript, script) {
			continue
		}

		txInputs = append(txInputs, transactionOutputTxInput{utxo})
	}

	return txInputs, nil
}

func (s *service) LockConnectorUtxos(ctx context.Context, utxos []ports.TxOutpoint) error {
	w, _ := s.loader.LoadedWallet()

	for _, utxo := range utxos {
		id, _ := chainhash.NewHashFromStr(utxo.GetTxid())
		if _, err := w.LeaseOutput(
			wtxmgr.LockID(id[:]),
			wire.OutPoint{
				Hash:  *id,
				Index: utxo.GetIndex(),
			},
			outputLockDuration,
		); err != nil {
			return err
		}
	}

	return nil
}

func (s *service) SelectUtxos(ctx context.Context, _ string, amount uint64) ([]ports.TxInput, uint64, error) {
	w, _ := s.loader.LoadedWallet()

	utxos, err := w.UnspentOutputs(wallet.OutputSelectionPolicy{
		Account:               s.accounts[mainAccount],
		RequiredConfirmations: 0, // allow uncomfirmed utxos
	})
	if err != nil {
		return nil, 0, err
	}

	coins := make([]wallet.Coin, 0, len(utxos))
	for _, utxo := range utxos {
		coins = append(coins, wallet.Coin{
			OutPoint: *wire.NewOutPoint(&utxo.OutPoint.Hash, utxo.OutPoint.Index),
			TxOut:    utxo.Output,
		})
	}

	arranged, err := wallet.CoinSelectionLargest.ArrangeCoins(
		coins,
		btcutil.Amount(0), // unused by CoinSelectionLargest strategy
	)
	if err != nil {
		return nil, 0, err
	}

	selectedAmount := uint64(0)
	selectedUtxos := make([]ports.TxInput, 0, len(arranged))

	for _, coin := range arranged {
		if selectedAmount >= amount {
			break
		}
		selectedAmount += uint64(coin.Value)
		selectedUtxos = append(selectedUtxos, coinTxInput{coin})
	}

	change := selectedAmount - amount

	return selectedUtxos, change, nil
}

func (s *service) SignTransaction(ctx context.Context, partialTx string, extractRawTx bool) (string, error) {
	ptx, err := psbt.NewFromRawBytes(
		strings.NewReader(partialTx),
		true,
	)
	if err != nil {
		return "", err
	}

	signedInputs, err := s.signPsbt(ptx)
	if err != nil {
		return "", err
	}

	if extractRawTx {
		// verify that all inputs are signed
		if len(signedInputs) != len(ptx.Inputs) {
			return "", errors.New("not all inputs are signed, unable to finalize the psbt")
		}

		if err := psbt.MaybeFinalizeAll(ptx); err != nil {
			return "", err
		}

		extracted, err := psbt.Extract(ptx)
		if err != nil {
			return "", err
		}

		var buf bytes.Buffer
		if err := extracted.Serialize(&buf); err != nil {
			return "", err
		}

		return hex.EncodeToString(buf.Bytes()), nil
	}

	return ptx.B64Encode()
}

func (s *service) SignTransactionTapscript(ctx context.Context, partialTx string, inputIndexes []int) (string, error) {
	partial, err := psbt.NewFromRawBytes(
		strings.NewReader(partialTx),
		true,
	)
	if err != nil {
		return "", err
	}

	if len(inputIndexes) == 0 {
		inputIndexes = make([]int, len(partial.Inputs))
		for i := range partial.Inputs {
			inputIndexes[i] = i
		}
	}

	signedInputs, err := s.signPsbt(partial)
	if err != nil {
		return "", err
	}

	for _, index := range inputIndexes {
		hasBeenSigned := false
		for _, signedIndex := range signedInputs {
			if signedIndex == uint32(index) {
				hasBeenSigned = true
				break
			}
		}

		if !hasBeenSigned {
			return "", fmt.Errorf("input %d has not been signed", index)
		}
	}

	return partial.B64Encode()
}

func (s *service) Status(ctx context.Context) (ports.WalletStatus, error) {
	w, isLoaded := s.loader.LoadedWallet()
	if !isLoaded {
		return status{isLoaded, false, false}, nil
	}

	return status{
		isLoaded,
		true,
		w.ChainSynced(),
	}, nil
}

func (s *service) WaitForSync(ctx context.Context, txid string) error {
	w, _ := s.loader.LoadedWallet()

	txhash, err := chainhash.NewHashFromStr(txid)
	if err != nil {
		return err
	}

	ticker := time.NewTicker(5 * time.Second)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			_, err := w.GetTransaction(*txhash)
			if err != nil {
				if strings.Contains(err.Error(), wallet.ErrNoTx.Error()) {
					continue
				}
				return err
			} else {
				ticker.Stop()
				return nil
			}
		}
	}
}

func (s *service) EstimateFees(ctx context.Context, partialTx string) (uint64, error) {
	feeRate, err := s.esploraClient.getFeeRate()
	if err != nil {
		return 0, err
	}

	partial, err := psbt.NewFromRawBytes(
		strings.NewReader(partialTx),
		true,
	)
	if err != nil {
		return 0, err
	}

	fee := feeRate * btcutil.Amount(partial.UnsignedTx.SerializeSize())
	return uint64(fee.ToUnit(btcutil.AmountSatoshi)), nil
}

func (s *service) WatchScripts(ctx context.Context, scripts []string) error {
	addresses := make([]btcutil.Address, 0, len(scripts))

	for _, script := range scripts {
		scriptBytes, err := hex.DecodeString(script)
		if err != nil {
			return err
		}

		addr, err := fromOutputScript(scriptBytes, s.chainParams())
		if err != nil {
			return err
		}

		addresses = append(addresses, addr)
	}

	s.watchedScriptsLock.Lock()
	for _, script := range scripts {
		s.watchedScripts[script] = struct{}{}
	}
	s.watchedScriptsLock.Unlock()

	if err := s.chainSource.NotifyReceived(addresses); err != nil {
		if err := s.UnwatchScripts(ctx, scripts); err != nil {
			return fmt.Errorf("error while unwatching scripts: %w", err)
		}

		return err
	}

	return nil
}

func (s *service) UnwatchScripts(ctx context.Context, scripts []string) error {
	s.watchedScriptsLock.Lock()
	defer s.watchedScriptsLock.Unlock()
	for _, script := range scripts {
		delete(s.watchedScripts, script)
	}

	return nil
}

func (s *service) GetNotificationChannel(ctx context.Context) <-chan map[string]ports.VtxoWithValue {
	ch := make(chan map[string]ports.VtxoWithValue)

	go func() {
		for n := range s.chainSource.Notifications() {
			switch m := n.(type) {
			case chain.RelevantTx:
				notification := s.castNotification(m)
				ch <- notification
			}
		}
	}()

	return ch
}

func (s *service) IsTransactionConfirmed(ctx context.Context, txid string) (isConfirmed bool, blocktime int64, err error) {
	return s.esploraClient.getTxStatus(txid)
}

func (s status) IsInitialized() bool {
	return s.initialized
}

func (s status) IsUnlocked() bool {
	return s.unlocked
}

func (s status) IsSynced() bool {
	return s.synced
}

func (s *service) castNotification(notif chain.RelevantTx) map[string]ports.VtxoWithValue {
	vtxos := make(map[string]ports.VtxoWithValue)

	s.watchedScriptsLock.Lock()
	defer s.watchedScriptsLock.Unlock()

	for outputIndex, txout := range notif.TxRecord.MsgTx.TxOut {
		script := hex.EncodeToString(txout.PkScript)

		if _, ok := s.watchedScripts[script]; !ok {
			continue
		}

		vtxos[script] = ports.VtxoWithValue{
			VtxoKey: domain.VtxoKey{
				Txid: notif.TxRecord.Hash.String(),
				VOut: uint32(outputIndex),
			},
			Value: uint64(txout.Value),
		}
	}

	return vtxos
}

func (s *service) getBalance(account accountName) (uint64, error) {
	w, _ := s.loader.LoadedWallet()

	accountsBalances, err := w.CalculateAccountBalances(s.accounts[account], 0)
	if err != nil {
		return 0, err
	}

	return uint64(accountsBalances.Total), nil
}

func (s *service) deriveNextAddress(account accountName) (btcutil.Address, error) {
	w, isLoaded := s.loader.LoadedWallet()
	if !isLoaded {
		return nil, errors.New("wallet not loaded")
	}

	return w.NewAddress(s.accounts[account], keyScope)
}

// status implements ports.WalletStatus interface
type status struct {
	initialized bool
	unlocked    bool
	synced      bool
}

func (s *service) chainParams() *chaincfg.Params {
	switch s.cfg.Network.Name {
	case common.Bitcoin.Name:
		return &chaincfg.MainNetParams
	case common.BitcoinTestNet.Name:
		return &chaincfg.TestNet3Params
	case common.BitcoinRegTest.Name:
		return &chaincfg.RegressionNetParams
	default:
		return &chaincfg.MainNetParams
	}
}

func fromOutputScript(script []byte, netParams *chaincfg.Params) (btcutil.Address, error) {
	return btcutil.NewAddressTaproot(script[2:], netParams)
}

func logger(subsystem string) btclog.Logger {
	return btclog.NewBackend(logrus.StandardLogger().Writer()).Logger(subsystem)
}
