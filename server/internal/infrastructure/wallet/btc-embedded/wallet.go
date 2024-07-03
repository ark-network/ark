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
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/btcsuite/btcwallet/wallet/txrules"
	"github.com/btcsuite/btcwallet/walletdb"
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
}

type accountName string

const (
	mainAccount      accountName = "main"
	connectorAccount accountName = "connector"
)

var (
	keyScope           = waddrmgr.KeyScopeBIP0044
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
func WithNeutrino() WalletOption {
	return func(s *service) error {
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

		neutrinoSvc, err := neutrino.NewChainService(config)
		if err != nil {
			return err
		}

		if err := neutrinoSvc.Start(); err != nil {
			return err
		}

		return WithChainSource(chain.NewNeutrinoClient(netParams, neutrinoSvc))(s)
	}
}

// NewService creates the wallet service, an option must be set to configure the chain source.
func NewService(cfg WalletConfig, options ...WalletOption) (ports.WalletService, error) {
	svc := &service{
		loader:             nil,
		accounts:           make(map[accountName]uint32),
		cfg:                cfg,
		esploraClient:      newEsploraClient(cfg.Network),
		watchedScriptsLock: sync.Mutex{},
		watchedScripts:     make(map[string]struct{}),
	}

	if err := svc.setWalletLoader(); err != nil {
		return nil, err
	}

	for _, option := range options {
		option(svc)
	}

	w, isLoaded := svc.loader.LoadedWallet()
	if !isLoaded {
		return nil, errors.New("wallet not loaded")
	}

	if svc.chainSource == nil {
		return nil, errors.New("chain source not provided, please use WalletOption to set it")
	}

	w.SynchronizeRPC(svc.chainSource)

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
		w, err := loader.CreateNewWallet(s.cfg.PublicPassword, s.cfg.PrivatePassword, nil, time.Now())
		if err != nil {
			return err
		}

		mainAccountNumber, err := w.NextAccount(keyScope, string(mainAccount))
		if err != nil {
			return err
		}

		connectorAccountNumber, err := w.NextAccount(keyScope, string(connectorAccount))
		if err != nil {
			return err
		}

		accounts[mainAccount] = mainAccountNumber
		accounts[connectorAccount] = connectorAccountNumber
	} else {
		w, err := loader.OpenExistingWallet(s.cfg.PublicPassword, true)
		if err != nil {
			return err
		}

		mainAccountNumber, err := w.AccountNumber(keyScope, string(mainAccount))
		if err != nil {
			return err
		}

		connectorAccountNumber, err := w.AccountNumber(keyScope, string(connectorAccount))
		if err != nil {
			return err
		}

		accounts[mainAccount] = mainAccountNumber
		accounts[connectorAccount] = connectorAccountNumber
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
	w, _ := s.loader.LoadedWallet()

	tx := &wire.MsgTx{}

	if err := tx.Deserialize(hex.NewDecoder(strings.NewReader(txHex))); err != nil {
		return "", err
	}

	if err := w.PublishTransaction(tx, ""); err != nil {
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
	w, _ := s.loader.LoadedWallet()

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

func (s *service) ListConnectorUtxos(ctx context.Context, connectorAddress string) ([]ports.TxInput, error) {
	w, _ := s.loader.LoadedWallet()

	addr, err := btcutil.DecodeAddress(connectorAddress, w.ChainParams())
	if err != nil {
		return nil, err
	}

	script := addr.ScriptAddress()

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
		RequiredConfirmations: 0,
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
	w, _ := s.loader.LoadedWallet()

	partial, err := psbt.NewFromRawBytes(
		strings.NewReader(partialTx),
		true,
	)
	if err != nil {
		return "", err
	}

	tx := partial.UnsignedTx

	additionalPrevoutScripts := make(map[wire.OutPoint][]byte)
	for inIndex, input := range partial.Inputs {
		additionalPrevoutScripts[tx.TxIn[inIndex].PreviousOutPoint] = input.WitnessUtxo.PkScript
	}

	sigErrors, err := w.SignTransaction(tx, txscript.SigHashAll, additionalPrevoutScripts, nil, nil)
	if err != nil {
		return "", err
	}

	if len(sigErrors) > 0 {
		return "", fmt.Errorf("error while signing transaction: %+v", sigErrors)
	}

	if extractRawTx {
		var buf bytes.Buffer
		if err := tx.Serialize(&buf); err != nil {
			return "", err
		}

		return hex.EncodeToString(buf.Bytes()), nil
	}

	for inIndex, input := range tx.TxIn {
		partial.Inputs[inIndex].FinalScriptSig = input.SignatureScript
	}

	return partial.B64Encode()
}

func (s *service) SignTransactionTapscript(ctx context.Context, partialTx string, inputIndexes []int) (string, error) {
	w, _ := s.loader.LoadedWallet()

	partial, err := psbt.NewFromRawBytes(
		strings.NewReader(partialTx),
		true,
	)
	if err != nil {
		return "", err
	}

	additionalPrevoutScripts := make(map[wire.OutPoint][]byte)

	for _, index := range inputIndexes {
		if index >= len(partial.Inputs) {
			return "", errors.New("input index out of range")
		}

		input := partial.Inputs[index]
		tapLeafScript := input.TaprootLeafScript[0]

		ctrlBlock, err := txscript.ParseControlBlock(tapLeafScript.ControlBlock)
		if err != nil {
			return "", err
		}

		tapscript := &waddrmgr.Tapscript{
			Type:           waddrmgr.TapscriptTypePartialReveal,
			ControlBlock:   ctrlBlock,
			RevealedScript: tapLeafScript.Script,
		}

		if _, err := w.ImportTaprootScript(keyScope, tapscript, nil, byte(txscript.TaprootWitnessVersion), false); err != nil {
			return "", err
		}

		additionalPrevoutScripts[partial.UnsignedTx.TxIn[index].PreviousOutPoint] = input.WitnessUtxo.PkScript
	}

	tx := partial.UnsignedTx

	sigErrors, err := w.SignTransaction(tx, txscript.SigHashDefault, additionalPrevoutScripts, nil, nil)
	if err != nil {
		return "", err
	}

	for _, sigError := range sigErrors {
		errorIndex := sigError.InputIndex

		for _, inputIndex := range inputIndexes {
			if errorIndex == uint32(inputIndex) {
				return "", fmt.Errorf("error while signing transaction: %+v", sigError)
			}
		}
	}

	for _, inputIndex := range inputIndexes {
		if err := psbt.Finalize(partial, inputIndex); err != nil {
			return "", err
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

	fee := txrules.FeeForSerializeSize(
		feeRate,
		partial.UnsignedTx.SerializeSize(),
	)

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
			switch n := n.(type) {
			case chain.RelevantTx:
				notification := s.castNotification(n)
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
	w, _ := s.loader.LoadedWallet()

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
	return btcutil.NewAddressTaproot(script, netParams)
}
