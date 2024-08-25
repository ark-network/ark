package btcwallet

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/bitcointree"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/ark-network/ark/server/internal/core/ports"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
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
	"github.com/lightningnetwork/lnd/blockcache"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwallet/btcwallet"
	log "github.com/sirupsen/logrus"
	"github.com/vulpemventures/go-bip39"
)

type WalletOption func(*service) error

type WalletConfig struct {
	Datadir    string
	Network    common.Network
	EsploraURL string
}

func (c WalletConfig) chainParams() *chaincfg.Params {
	mutinyNetSigNetParams := chaincfg.CustomSignetParams(common.MutinyNetChallenge, nil)
	mutinyNetSigNetParams.TargetTimePerBlock = common.MutinyNetBlockTime
	switch c.Network.Name {
	case common.Bitcoin.Name:
		return &chaincfg.MainNetParams
	case common.BitcoinTestNet.Name:
		return &chaincfg.TestNet3Params
	case common.BitcoinRegTest.Name:
		return &chaincfg.RegressionNetParams
	case common.BitcoinSigNet.Name:
		return &mutinyNetSigNetParams
	default:
		return &chaincfg.MainNetParams
	}
}

type accountName string

const (
	mainAccount      accountName = "main"
	connectorAccount accountName = "connector"
	aspKeyAccount    accountName = "aspkey"
)

var (
	ErrWalletNotLoaded = fmt.Errorf("wallet not loaded, create or unlock it first")
	p2wpkhKeyScope     = waddrmgr.KeyScopeBIP0084
	p2trKeyScope       = waddrmgr.KeyScopeBIP0086
	outputLockDuration = time.Minute
)

type service struct {
	wallet *btcwallet.BtcWallet
	cfg    WalletConfig

	chainSource chain.Interface
	scanner     chain.Interface

	esploraClient *esploraClient

	watchedScriptsLock sync.RWMutex
	watchedScripts     map[string]struct{}

	aspTaprootAddr waddrmgr.ManagedPubKeyAddress
}

// WithNeutrino creates a start a neutrino node using the provided service datadir
func WithNeutrino(initialPeer string) WalletOption {
	return func(s *service) error {
		if s.cfg.Network.Name == common.BitcoinRegTest.Name && len(initialPeer) == 0 {
			return fmt.Errorf("initial neutrino peer required for regtest network, set NEUTRINO_PEER env var")
		}

		db, err := createOrOpenWalletDB(s.cfg.Datadir + "/neutrino.db")
		if err != nil {
			return err
		}

		netParams := s.cfg.chainParams()

		config := neutrino.Config{
			DataDir:     s.cfg.Datadir,
			ChainParams: *netParams,
			Database:    db,
		}

		if len(initialPeer) > 0 {
			config.AddPeers = []string{initialPeer}
		}

		neutrino.UseLogger(logger("neutrino"))
		btcwallet.UseLogger(logger("btcwallet"))

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
		scanner := chain.NewNeutrinoClient(netParams, neutrinoSvc)
		if err := withChainSource(chainSrc)(s); err != nil {
			return err
		}
		return withScanner(scanner)(s)
	}
}

func WithPollingBitcoind(host, user, pass string) WalletOption {
	return func(s *service) error {
		netParams := s.cfg.chainParams()
		// Create a new bitcoind configuration
		bitcoindConfig := &chain.BitcoindConfig{
			ChainParams: netParams,
			Host:        host,
			User:        user,
			Pass:        pass,
			PollingConfig: &chain.PollingConfig{
				BlockPollingInterval:    10 * time.Second,
				TxPollingInterval:       5 * time.Second,
				TxPollingIntervalJitter: 0.1,
				RPCBatchSize:            20,
				RPCBatchInterval:        1 * time.Second,
			},
		}

		chain.UseLogger(logger("chain"))

		// Create the BitcoindConn first
		bitcoindConn, err := chain.NewBitcoindConn(bitcoindConfig)
		if err != nil {
			return fmt.Errorf("failed to create bitcoind connection: %w", err)
		}

		// Start the bitcoind connection
		if err := bitcoindConn.Start(); err != nil {
			return fmt.Errorf("failed to start bitcoind connection: %w", err)
		}

		// Now create the BitcoindClient using the connection
		chainClient := bitcoindConn.NewBitcoindClient()

		// Start the chain client
		if err := chainClient.Start(); err != nil {
			bitcoindConn.Stop()
			return fmt.Errorf("failed to start bitcoind client: %w", err)
		}

		// wait for bitcoind to sync
		for !chainClient.IsCurrent() {
			time.Sleep(1 * time.Second)
		}

		// Set up the wallet as chain source and scanner
		if err := withChainSource(chainClient)(s); err != nil {
			chainClient.Stop()
			bitcoindConn.Stop()
			return fmt.Errorf("failed to set chain source: %w", err)
		}

		if err := withScanner(chainClient)(s); err != nil {
			chainClient.Stop()
			bitcoindConn.Stop()
			return fmt.Errorf("failed to set scanner: %w", err)
		}

		return nil
	}
}

// NewService creates the wallet service, an option must be set to configure the chain source.
func NewService(cfg WalletConfig, options ...WalletOption) (ports.WalletService, error) {
	wallet.UseLogger(logger("wallet"))

	svc := &service{
		cfg:                cfg,
		esploraClient:      &esploraClient{url: cfg.EsploraURL},
		watchedScriptsLock: sync.RWMutex{},
		watchedScripts:     make(map[string]struct{}),
	}

	for _, option := range options {
		if err := option(svc); err != nil {
			return nil, err
		}
	}

	return svc, nil
}

func (s *service) Close() {
	if s.walletLoaded() {
		if err := s.wallet.Stop(); err != nil {
			log.WithError(err).Warn("failed to gracefully stop the wallet, forcing shutdown")
		}
	}
}

func (s *service) GenSeed(_ context.Context) (string, error) {
	entropy, err := bip39.NewEntropy(256)
	if err != nil {
		return "", err
	}
	return bip39.NewMnemonic(entropy)
}

func (s *service) Create(_ context.Context, seed, password string) error {
	return s.create(seed, password, 0)
}

func (s *service) Restore(_ context.Context, seed, password string) error {
	return s.create(seed, password, 100)
}

func (s *service) Unlock(_ context.Context, password string) error {
	if !s.walletLoaded() {
		pwd := []byte(password)
		opt := btcwallet.LoaderWithLocalWalletDB(s.cfg.Datadir, false, time.Minute)
		config := btcwallet.Config{
			LogDir:                s.cfg.Datadir,
			PrivatePass:           pwd,
			PublicPass:            pwd,
			Birthday:              time.Now(),
			RecoveryWindow:        0,
			NetParams:             s.cfg.chainParams(),
			LoaderOptions:         []btcwallet.LoaderOption{opt},
			CoinSelectionStrategy: wallet.CoinSelectionLargest,
			ChainSource:           s.chainSource,
		}
		blockCache := blockcache.NewBlockCache(2 * 1024 * 1024 * 1024)

		wallet, err := btcwallet.New(config, blockCache)
		if err != nil {
			return fmt.Errorf("failed to setup wallet loader: %s", err)
		}

		if err := wallet.Start(); err != nil {
			return fmt.Errorf("failed to start wallet: %s", err)
		}

		for {
			if !wallet.InternalWallet().ChainSynced() {
				log.Debugf("waiting sync: current height %d", wallet.InternalWallet().Manager.SyncedTo().Height)
				time.Sleep(3 * time.Second)
				continue
			}
			break
		}
		log.Debugf("chain synced")

		addrs, err := wallet.ListAddresses(string(aspKeyAccount), false)
		if err != nil {
			return err
		}
		for info, addrs := range addrs {
			if info.AccountName != string(aspKeyAccount) {
				continue
			}

			for _, addr := range addrs {
				if addr.Internal {
					continue
				}

				splittedPath := strings.Split(addr.DerivationPath, "/")
				last := splittedPath[len(splittedPath)-1]
				if last == "0" {
					decoded, err := btcutil.DecodeAddress(addr.Address, s.cfg.chainParams())
					if err != nil {
						return err
					}

					infos, err := wallet.AddressInfo(decoded)
					if err != nil {
						return err
					}

					managedPubkeyAddr, ok := infos.(waddrmgr.ManagedPubKeyAddress)
					if !ok {
						return fmt.Errorf("failed to cast address to managed pubkey address")
					}

					s.aspTaprootAddr = managedPubkeyAddr
					break
				}
			}
		}

		s.wallet = wallet
		return nil
	}
	return s.wallet.InternalWallet().Unlock([]byte(password), nil)
}

func (s *service) Lock(_ context.Context, _ string) error {
	if !s.walletLoaded() {
		return ErrWalletNotLoaded
	}

	s.wallet.InternalWallet().Lock()
	return nil
}

func (s *service) BroadcastTransaction(ctx context.Context, txHex string) (string, error) {
	if err := s.esploraClient.broadcast(txHex); err != nil {
		return "", err
	}

	var tx wire.MsgTx
	if err := tx.Deserialize(hex.NewDecoder(strings.NewReader(txHex))); err != nil {
		return "", err
	}
	if err := s.wallet.PublishTransaction(&tx, ""); err != nil {
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
		return nil, fmt.Errorf("no addresses derived")
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
	return s.aspTaprootAddr.PubKey(), nil
}

func (s *service) ListConnectorUtxos(ctx context.Context, connectorAddress string) ([]ports.TxInput, error) {
	w := s.wallet.InternalWallet()

	addr, err := btcutil.DecodeAddress(connectorAddress, w.ChainParams())
	if err != nil {
		return nil, err
	}

	script, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return nil, err
	}

	connectorAccountNumber, err := w.AccountNumber(p2wpkhKeyScope, string(connectorAccount))
	if err != nil {
		return nil, err
	}

	utxos, err := w.UnspentOutputs(wallet.OutputSelectionPolicy{
		Account:               connectorAccountNumber,
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
	w := s.wallet.InternalWallet()

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
	w := s.wallet.InternalWallet()

	mainAccountNumber, err := w.AccountNumber(p2wpkhKeyScope, string(mainAccount))
	if err != nil {
		return nil, 0, err
	}

	utxos, err := w.UnspentOutputs(wallet.OutputSelectionPolicy{
		Account:               mainAccountNumber,
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

	signedInputs, err := s.signPsbt(ptx, nil)
	if err != nil {
		return "", err
	}
	if extractRawTx {
		// verify that all inputs are signed
		if len(signedInputs) != len(ptx.Inputs) {
			return "", fmt.Errorf("not all inputs are signed, unable to finalize the psbt")
		}

		for i, in := range ptx.Inputs {
			isTaproot := txscript.IsPayToTaproot(in.WitnessUtxo.PkScript)
			if isTaproot && len(in.TaprootLeafScript) > 0 {
				closure, err := bitcointree.DecodeClosure(in.TaprootLeafScript[0].Script)
				if err != nil {
					return "", err
				}

				witness := make(wire.TxWitness, 4)

				castClosure, isTaprootMultisig := closure.(*bitcointree.MultisigClosure)
				if isTaprootMultisig {
					ownerPubkey := schnorr.SerializePubKey(castClosure.Pubkey)
					aspKey := schnorr.SerializePubKey(castClosure.AspPubkey)

					for _, sig := range in.TaprootScriptSpendSig {
						if bytes.Equal(sig.XOnlyPubKey, ownerPubkey) {
							witness[0] = sig.Signature
						}

						if bytes.Equal(sig.XOnlyPubKey, aspKey) {
							witness[1] = sig.Signature
						}
					}

					witness[2] = in.TaprootLeafScript[0].Script
					witness[3] = in.TaprootLeafScript[0].ControlBlock

					for idw, w := range witness {
						if w == nil {
							return "", fmt.Errorf("missing witness element %d, cannot finalize taproot mutlisig input %d", idw, i)
						}
					}

					var witnessBuf bytes.Buffer

					if err := psbt.WriteTxWitness(&witnessBuf, witness); err != nil {
						return "", err
					}

					ptx.Inputs[i].FinalScriptWitness = witnessBuf.Bytes()
					continue
				}

			}

			if err := psbt.Finalize(ptx, i); err != nil {
				return "", fmt.Errorf("failed to finalize input %d: %w", i, err)
			}
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

	signedInputs, err := s.signPsbt(partial, inputIndexes)
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
	if !s.walletLoaded() {
		return status{
			initialized: s.walletInitialized(),
		}, nil
	}

	w := s.wallet.InternalWallet()
	return status{
		true,
		!w.Manager.IsLocked(),
		w.ChainSynced(),
	}, nil
}

func (s *service) WaitForSync(ctx context.Context, txid string) error {
	w := s.wallet.InternalWallet()

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

		addr, err := fromOutputScript(scriptBytes, s.cfg.chainParams())
		if err != nil {
			return err
		}

		addresses = append(addresses, addr)
	}

	if err := s.scanner.NotifyReceived(addresses); err != nil {
		if err := s.UnwatchScripts(ctx, scripts); err != nil {
			return fmt.Errorf("error while unwatching scripts: %w", err)
		}

		return err
	}

	s.watchedScriptsLock.Lock()
	defer s.watchedScriptsLock.Unlock()

	for _, script := range scripts {
		s.watchedScripts[script] = struct{}{}
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

func (s *service) GetNotificationChannel(
	ctx context.Context,
) <-chan map[string]ports.VtxoWithValue {
	ch := make(chan map[string]ports.VtxoWithValue)

	go func() {
		for n := range s.scanner.Notifications() {
			switch m := n.(type) {
			case chain.RelevantTx:
				notification := s.castNotification(m.TxRecord)
				ch <- notification
			case chain.FilteredBlockConnected:
				for _, tx := range m.RelevantTxs {
					notification := s.castNotification(tx)
					ch <- notification
				}
			}
		}
	}()

	return ch
}

func (s *service) IsTransactionConfirmed(
	ctx context.Context, txid string,
) (isConfirmed bool, blocktime int64, err error) {
	return s.esploraClient.getTxStatus(txid)
}

func (s *service) GetTransaction(ctx context.Context, txid string) (string, error) {
	tx, err := s.esploraClient.getTx(txid)
	if err != nil {
		return "", err
	}

	if tx == nil {
		return "", fmt.Errorf("transaction not found")
	}

	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		return "", err
	}

	return hex.EncodeToString(buf.Bytes()), nil
}

func (s *service) castNotification(tx *wtxmgr.TxRecord) map[string]ports.VtxoWithValue {
	vtxos := make(map[string]ports.VtxoWithValue)

	s.watchedScriptsLock.RLock()
	defer s.watchedScriptsLock.RUnlock()

	for outputIndex, txout := range tx.MsgTx.TxOut {
		script := hex.EncodeToString(txout.PkScript)
		if _, ok := s.watchedScripts[script]; !ok {
			continue
		}

		vtxos[script] = ports.VtxoWithValue{
			VtxoKey: domain.VtxoKey{
				Txid: tx.Hash.String(),
				VOut: uint32(outputIndex),
			},
			Value: uint64(txout.Value),
		}
	}

	return vtxos
}

func (s *service) create(mnemonic, password string, addrGap uint32) error {
	if len(mnemonic) <= 0 {
		return fmt.Errorf("missing hd seed")
	}
	if len(password) <= 0 {
		return fmt.Errorf("missing password")
	}

	pwd := []byte(password)
	seed := bip39.NewSeed(mnemonic, password)
	opt := btcwallet.LoaderWithLocalWalletDB(s.cfg.Datadir, false, time.Minute)
	config := btcwallet.Config{
		LogDir:                s.cfg.Datadir,
		PrivatePass:           pwd,
		PublicPass:            pwd,
		Birthday:              time.Now(),
		RecoveryWindow:        addrGap,
		HdSeed:                seed,
		NetParams:             s.cfg.chainParams(),
		LoaderOptions:         []btcwallet.LoaderOption{opt},
		CoinSelectionStrategy: wallet.CoinSelectionLargest,
		ChainSource:           s.chainSource,
	}
	blockCache := blockcache.NewBlockCache(2 * 1024 * 1024 * 1024)

	wallet, err := btcwallet.New(config, blockCache)
	if err != nil {
		return fmt.Errorf("failed to setup wallet loader: %s", err)
	}

	if err := wallet.Start(); err != nil {
		return fmt.Errorf("failed to start wallet: %s", err)
	}
	if err := s.initWallet(wallet); err != nil {
		return err
	}

	for {
		if !wallet.InternalWallet().ChainSynced() {
			log.Debugf("waiting sync: current height %d", wallet.InternalWallet().Manager.SyncedTo().Height)
			time.Sleep(3 * time.Second)
			continue
		}
		break
	}
	log.Debugf("chain synced")

	if addrGap > 0 {
		// TODO: fix rescan
		if err := wallet.InternalWallet().Rescan(nil, nil); err != nil {
			return err
		}
	}

	wallet.InternalWallet().Lock()
	s.wallet = wallet
	return nil
}

func (s *service) initWallet(wallet *btcwallet.BtcWallet) error {
	w := wallet.InternalWallet()

	walletAccounts, err := w.Accounts(p2wpkhKeyScope)
	if err != nil {
		return fmt.Errorf("failed to list wallet accounts: %s", err)
	}
	var mainAccountNumber, connectorAccountNumber, aspKeyAccountNumber uint32
	if walletAccounts != nil {
		for _, account := range walletAccounts.Accounts {
			switch account.AccountName {
			case string(mainAccount):
				mainAccountNumber = account.AccountNumber
			case string(connectorAccount):
				connectorAccountNumber = account.AccountNumber
			case string(aspKeyAccount):
				aspKeyAccountNumber = account.AccountNumber
			default:
				continue
			}
		}
	}

	if mainAccountNumber == 0 && connectorAccountNumber == 0 && aspKeyAccountNumber == 0 {
		log.Debug("creating default accounts for ark wallet...")
		mainAccountNumber, err = w.NextAccount(p2wpkhKeyScope, string(mainAccount))
		if err != nil {
			return fmt.Errorf("failed to create %s: %s", mainAccount, err)
		}

		connectorAccountNumber, err = w.NextAccount(p2wpkhKeyScope, string(connectorAccount))
		if err != nil {
			return fmt.Errorf("failed to create %s: %s", connectorAccount, err)
		}

		aspKeyAccountNumber, err = w.NextAccount(p2trKeyScope, string(aspKeyAccount))
		if err != nil {
			return fmt.Errorf("failed to create %s: %s", aspKeyAccount, err)
		}
	}

	log.Debugf("main account number: %d", mainAccountNumber)
	log.Debugf("connector account number: %d", connectorAccountNumber)
	log.Debugf("asp key account number: %d", aspKeyAccountNumber)

	addrs, err := wallet.ListAddresses(string(aspKeyAccount), false)
	if err != nil {
		return err
	}

	if len(addrs) == 0 {
		aspKeyAddr, err := wallet.NewAddress(lnwallet.TaprootPubkey, false, string(aspKeyAccount))
		if err != nil {
			return err
		}

		addrInfos, err := wallet.AddressInfo(aspKeyAddr)
		if err != nil {
			return err
		}

		managedAddr, ok := addrInfos.(waddrmgr.ManagedPubKeyAddress)
		if !ok {
			return fmt.Errorf("failed to cast address to managed pubkey address")
		}

		s.aspTaprootAddr = managedAddr
	} else {
		for info, addrs := range addrs {
			if info.AccountName != string(aspKeyAccount) {
				continue
			}

			for _, addr := range addrs {
				if addr.Internal {
					continue
				}

				splittedPath := strings.Split(addr.DerivationPath, "/")
				last := splittedPath[len(splittedPath)-1]
				if last == "0" {
					decoded, err := btcutil.DecodeAddress(addr.Address, s.cfg.chainParams())
					if err != nil {
						return err
					}

					infos, err := wallet.AddressInfo(decoded)
					if err != nil {
						return err
					}

					managedPubkeyAddr, ok := infos.(waddrmgr.ManagedPubKeyAddress)
					if !ok {
						return fmt.Errorf("failed to cast address to managed pubkey address")
					}

					s.aspTaprootAddr = managedPubkeyAddr
					break
				}
			}
		}
	}

	return nil
}

func (s *service) getBalance(account accountName) (uint64, error) {
	if !s.walletLoaded() {
		return 0, ErrWalletNotLoaded
	}

	balance, err := s.wallet.ConfirmedBalance(0, string(account))
	if err != nil {
		return 0, err
	}

	return uint64(balance), nil
}

// this only supports deriving segwit v0 accounts
func (s *service) deriveNextAddress(account accountName) (btcutil.Address, error) {
	if !s.walletLoaded() {
		return nil, ErrWalletNotLoaded
	}

	return s.wallet.NewAddress(lnwallet.WitnessPubKey, false, string(account))
}

func (s *service) walletLoaded() bool {
	return s.wallet != nil
}

func (s *service) walletInitialized() bool {
	opts := []btcwallet.LoaderOption{btcwallet.LoaderWithLocalWalletDB(s.cfg.Datadir, false, time.Minute)}
	loader, err := btcwallet.NewWalletLoader(
		s.cfg.chainParams(), 0, opts...,
	)
	if err != nil {
		return false
	}

	exist, _ := loader.WalletExists()

	return exist
}

func withChainSource(chainSource chain.Interface) WalletOption {
	return func(s *service) error {
		if s.chainSource != nil {
			return fmt.Errorf("chain source already set")
		}

		s.chainSource = chainSource
		return nil
	}
}

func withScanner(chainSource chain.Interface) WalletOption {
	return func(s *service) error {
		if s.scanner != nil {
			return fmt.Errorf("scanner already set")
		}
		if err := chainSource.Start(); err != nil {
			return fmt.Errorf("failed to start scanner: %s", err)
		}
		s.scanner = chainSource
		return nil
	}
}

func createOrOpenWalletDB(path string) (walletdb.DB, error) {
	db, err := walletdb.Open("bdb", path, true, 60*time.Second)
	if err == nil {
		return db, nil
	}
	if err != walletdb.ErrDbDoesNotExist {
		return nil, err
	}
	return walletdb.Create("bdb", path, true, 60*time.Second)
}

// status implements ports.WalletStatus interface
type status struct {
	initialized bool
	unlocked    bool
	synced      bool
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

func fromOutputScript(script []byte, netParams *chaincfg.Params) (btcutil.Address, error) {
	return btcutil.NewAddressTaproot(script[2:], netParams)
}

func logger(subsystem string) btclog.Logger {
	return btclog.NewBackend(log.StandardLogger().Writer()).Logger(subsystem)
}
