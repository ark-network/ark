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
	"github.com/btcsuite/btcd/rpcclient"
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
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwallet/btcwallet"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	log "github.com/sirupsen/logrus"
	"github.com/vulpemventures/go-bip39"
)

type WalletOption func(*service) error

type WalletConfig struct {
	Datadir string
	Network common.Network
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
	// p2wkh scope
	mainAccount accountName = "default" // default is always the first account (index 0)

	// p2tr scope
	connectorAccount accountName = "default"

	// this account won't be restored by lnd, but it's not a problem cause it does not track any funds
	// it's used to derive a constant public key to be used as "ASP key" in Vtxo scripts
	aspKeyAccount accountName = "asp"

	// https://github.com/bitcoin/bitcoin/blob/439e58c4d8194ca37f70346727d31f52e69592ec/src/policy/policy.cpp#L23C8-L23C11
	// biggest input size to compute the maximum dust amount
	biggestInputSize = 148 + 182 // = 330 vbytes
)

var (
	ErrWalletNotLoaded = fmt.Errorf("wallet not loaded, create or unlock it first")
	p2wpkhKeyScope     = waddrmgr.KeyScopeBIP0084
	p2trKeyScope       = waddrmgr.KeyScopeBIP0086
	outputLockDuration = time.Minute
)

// add additional chain API not supported by the chain.Interface type
type extraChainAPI interface {
	getTx(txid string) (*wire.MsgTx, error)
	getTxStatus(txid string) (isConfirmed bool, blockHeight, blocktime int64, err error)
	broadcast(txHex string) error
}

type service struct {
	wallet *btcwallet.BtcWallet
	cfg    WalletConfig

	chainSource  chain.Interface
	scanner      chain.Interface
	extraAPI     extraChainAPI
	feeEstimator chainfee.Estimator

	watchedScriptsLock sync.RWMutex
	watchedScripts     map[string]struct{}

	// holds the data related to the ASP key used in Vtxo scripts
	aspKeyAddr waddrmgr.ManagedPubKeyAddress
}

// WithNeutrino creates a start a neutrino node using the provided service datadir
func WithNeutrino(initialPeer string, esploraURL string) WalletOption {
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

		esploraClient := &esploraClient{url: esploraURL}
		estimator, err := chainfee.NewWebAPIEstimator(esploraClient, true, 5*time.Minute, 20*time.Minute)
		if err != nil {
			return err
		}

		if err := withExtraAPI(esploraClient)(s); err != nil {
			return err
		}

		if err := withFeeEstimator(estimator)(s); err != nil {
			return err
		}

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

		estimator, err := chainfee.NewBitcoindEstimator(
			rpcclient.ConnConfig{
				Host: bitcoindConfig.Host,
				User: bitcoindConfig.User,
				Pass: bitcoindConfig.Pass,
			},
			"CONSERVATIVE",
			chainfee.AbsoluteFeePerKwFloor,
		)
		if err != nil {
			return fmt.Errorf("failed to create bitcoind fee estimator: %w", err)
		}

		if err := withExtraAPI(&bitcoindRPCClient{chainClient})(s); err != nil {
			return err
		}

		if err := withFeeEstimator(estimator)(s); err != nil {
			return err
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
	return s.create(seed, password, 2000) // restore = create with a bigger recovery window
}

func (s *service) Unlock(_ context.Context, password string) error {
	if !s.walletInitialized() {
		return fmt.Errorf("wallet not initialized")
	}

	if !s.walletLoaded() {
		pwd := []byte(password)
		opt := btcwallet.LoaderWithLocalWalletDB(s.cfg.Datadir, false, time.Minute)
		config := btcwallet.Config{
			LogDir:                s.cfg.Datadir,
			PrivatePass:           pwd,
			PublicPass:            pwd,
			RecoveryWindow:        512,
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

					s.aspKeyAddr = managedPubkeyAddr
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
	if err := s.extraAPI.broadcast(txHex); err != nil {
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
	utxos, err := s.listUtxos(p2trKeyScope)
	if err != nil {
		return 0, 0, err
	}

	amount := uint64(0)
	for _, utxo := range utxos {
		amount += uint64(utxo.Output.Value)
	}

	return amount, 0, nil
}

func (s *service) MainAccountBalance(ctx context.Context) (uint64, uint64, error) {
	utxos, err := s.listUtxos(p2wpkhKeyScope)
	if err != nil {
		return 0, 0, err
	}

	amount := uint64(0)
	for _, utxo := range utxos {
		amount += uint64(utxo.Output.Value)
	}

	return amount, 0, nil
}

func (s *service) DeriveAddresses(ctx context.Context, num int) ([]string, error) {
	addresses := make([]string, 0, num)

	for i := 0; i < num; i++ {
		addr, err := s.deriveNextAddress()
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
	addr, err := s.wallet.NewAddress(lnwallet.TaprootPubkey, false, string(connectorAccount))
	if err != nil {
		return "", err
	}

	return addr.EncodeAddress(), nil
}

func (s *service) GetPubkey(ctx context.Context) (*secp256k1.PublicKey, error) {
	return s.aspKeyAddr.PubKey(), nil
}

func (s *service) GetForfeitAddress(ctx context.Context) (string, error) {
	addrs, err := s.wallet.ListAddresses(string(mainAccount), false)
	if err != nil {
		return "", err
	}

	if len(addrs) == 0 {
		addr, err := s.deriveNextAddress()
		if err != nil {
			return "", err
		}

		return addr.EncodeAddress(), nil
	}

	for info, addrs := range addrs {
		if info.KeyScope != p2wpkhKeyScope {
			continue
		}

		if info.AccountName != string(mainAccount) {
			continue
		}

		for _, addr := range addrs {
			if addr.Internal {
				continue
			}

			splittedPath := strings.Split(addr.DerivationPath, "/")
			last := splittedPath[len(splittedPath)-1]
			if last == "0" {
				return addr.Address, nil
			}
		}
	}

	return "", fmt.Errorf("forfeit address not found")
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

	utxos, err := s.listUtxos(p2trKeyScope)
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

	utxos, err := s.listUtxos(p2wpkhKeyScope)
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

	if selectedAmount < amount {
		return nil, 0, fmt.Errorf("insufficient funds to select %d, only %d available", amount, selectedAmount)
	}

	for _, utxo := range selectedUtxos {
		if _, err := w.LeaseOutput(
			wtxmgr.LockID(utxo.(coinTxInput).Hash),
			wire.OutPoint{
				Hash:  utxo.(coinTxInput).Hash,
				Index: utxo.(coinTxInput).Index,
			},
			outputLockDuration,
		); err != nil {
			return nil, 0, err
		}
	}
	return selectedUtxos, selectedAmount - amount, nil
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

func (s *service) MinRelayFeeRate(ctx context.Context) chainfee.SatPerKVByte {
	return s.feeEstimator.RelayFeePerKW().FeePerKVByte()
}

func (s *service) MinRelayFee(ctx context.Context, vbytes uint64) (uint64, error) {
	fee := s.feeEstimator.RelayFeePerKW().FeeForVByte(lntypes.VByte(vbytes))
	return uint64(fee.ToUnit(btcutil.AmountSatoshi)), nil
}

func (s *service) EstimateFees(ctx context.Context, partialTx string) (uint64, error) {
	feeRate, err := s.feeEstimator.EstimateFeePerKW(1)
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

	weightEstimator := &input.TxWeightEstimator{}

	for _, input := range partial.Inputs {
		if input.WitnessUtxo == nil {
			return 0, fmt.Errorf("missing witness utxo for input")
		}

		script, err := txscript.ParsePkScript(input.WitnessUtxo.PkScript)
		if err != nil {
			return 0, err
		}

		switch script.Class() {
		case txscript.PubKeyHashTy:
			weightEstimator.AddP2PKHInput()
		case txscript.WitnessV0PubKeyHashTy:
			weightEstimator.AddP2WKHInput()
		case txscript.WitnessV1TaprootTy:
			if len(input.TaprootLeafScript) > 0 {
				leaf := input.TaprootLeafScript[0]
				ctrlBlock, err := txscript.ParseControlBlock(leaf.ControlBlock)
				if err != nil {
					return 0, err
				}

				weightEstimator.AddTapscriptInput(64*2, &waddrmgr.Tapscript{
					RevealedScript: leaf.Script,
					ControlBlock:   ctrlBlock,
				})
			} else {
				weightEstimator.AddTaprootKeySpendInput(txscript.SigHashDefault)
			}
		default:
			return 0, fmt.Errorf("unsupported script type: %v", script.Class())
		}
	}

	for _, output := range partial.UnsignedTx.TxOut {
		script, err := txscript.ParsePkScript(output.PkScript)
		if err != nil {
			return 0, err
		}

		switch script.Class() {
		case txscript.PubKeyHashTy:
			weightEstimator.AddP2PKHOutput()
		case txscript.WitnessV0PubKeyHashTy:
			weightEstimator.AddP2WKHOutput()
		case txscript.ScriptHashTy:
			weightEstimator.AddP2SHOutput()
		case txscript.WitnessV0ScriptHashTy:
			weightEstimator.AddP2WSHOutput()
		case txscript.WitnessV1TaprootTy:
			weightEstimator.AddP2TROutput()
		default:
			return 0, fmt.Errorf("unsupported script type: %v", script.Class())
		}
	}

	fee := feeRate.FeeForVByte(lntypes.VByte(weightEstimator.VSize()))
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
) <-chan map[string][]ports.VtxoWithValue {
	ch := make(chan map[string][]ports.VtxoWithValue)

	go func() {
		const maxCacheSize = 100
		sentTxs := make(map[chainhash.Hash]struct{})

		cache := func(hash chainhash.Hash) {
			if len(sentTxs) > maxCacheSize {
				sentTxs = make(map[chainhash.Hash]struct{})
			}

			sentTxs[hash] = struct{}{}
		}

		for n := range s.scanner.Notifications() {
			switch m := n.(type) {
			case chain.RelevantTx:
				if _, sent := sentTxs[m.TxRecord.Hash]; sent {
					continue
				}
				notification := s.castNotification(m.TxRecord)
				cache(m.TxRecord.Hash)
				ch <- notification
			case chain.FilteredBlockConnected:
				for _, tx := range m.RelevantTxs {
					if _, sent := sentTxs[tx.Hash]; sent {
						continue
					}
					notification := s.castNotification(tx)
					cache(tx.Hash)
					ch <- notification
				}
			}
		}
	}()

	return ch
}

func (s *service) IsTransactionConfirmed(
	ctx context.Context, txid string,
) (isConfirmed bool, blocknumber int64, blocktime int64, err error) {
	return s.extraAPI.getTxStatus(txid)
}

func (s *service) GetDustAmount(
	ctx context.Context,
) (uint64, error) {
	return s.MinRelayFee(ctx, biggestInputSize)
}

func (s *service) GetTransaction(ctx context.Context, txid string) (string, error) {
	tx, err := s.extraAPI.getTx(txid)
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

func (s *service) castNotification(tx *wtxmgr.TxRecord) map[string][]ports.VtxoWithValue {
	vtxos := make(map[string][]ports.VtxoWithValue)

	s.watchedScriptsLock.RLock()
	defer s.watchedScriptsLock.RUnlock()

	for outputIndex, txout := range tx.MsgTx.TxOut {
		script := hex.EncodeToString(txout.PkScript)
		if _, ok := s.watchedScripts[script]; !ok {
			continue
		}

		if len(vtxos[script]) <= 0 {
			vtxos[script] = make([]ports.VtxoWithValue, 0)
		}

		vtxos[script] = append(vtxos[script], ports.VtxoWithValue{
			VtxoKey: domain.VtxoKey{
				Txid: tx.Hash.String(),
				VOut: uint32(outputIndex),
			},
			Value: uint64(txout.Value),
		})
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

	if err := wallet.InternalWallet().Unlock([]byte(password), nil); err != nil {
		return fmt.Errorf("failed to unlock wallet: %s", err)
	}

	defer wallet.InternalWallet().Lock()

	if err := s.initAspKeyAccount(wallet); err != nil {
		return err
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

	if err := s.initAspKeyAddress(wallet); err != nil {
		return err
	}

	s.wallet = wallet
	return nil
}

// initAspKeyAccount creates the asp key account if it doesn't exist
func (s *service) initAspKeyAccount(wallet *btcwallet.BtcWallet) error {
	w := wallet.InternalWallet()

	p2trAccounts, err := w.Accounts(p2trKeyScope)
	if err != nil {
		return fmt.Errorf("failed to list wallet accounts: %s", err)
	}

	var aspKeyAccountNumber uint32

	if p2trAccounts != nil {
		for _, account := range p2trAccounts.Accounts {
			if account.AccountName == string(aspKeyAccount) {
				aspKeyAccountNumber = account.AccountNumber
				break
			}
		}
	}

	if aspKeyAccountNumber == 0 {
		log.Debug("creating asp key account")
		aspKeyAccountNumber, err = w.NextAccount(p2trKeyScope, string(aspKeyAccount))
		if err != nil {
			return fmt.Errorf("failed to create %s: %s", aspKeyAccount, err)
		}
	}

	log.Debugf("key account number: %d", aspKeyAccountNumber)

	return nil
}

// initAspKeyAddress generates the asp key address if it doesn't exist
// it also cache the address in s.aspKeyAddr field
func (s *service) initAspKeyAddress(wallet *btcwallet.BtcWallet) error {
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

		s.aspKeyAddr = managedAddr
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

					s.aspKeyAddr = managedPubkeyAddr
					break
				}
			}
		}
	}

	return nil
}

func (s *service) deriveNextAddress() (btcutil.Address, error) {
	if !s.walletLoaded() {
		return nil, ErrWalletNotLoaded
	}

	return s.wallet.NewAddress(lnwallet.WitnessPubKey, false, string(mainAccount))
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

func (s *service) listUtxos(scope waddrmgr.KeyScope) ([]*wallet.TransactionOutput, error) {
	w := s.wallet.InternalWallet()

	accountNumber, err := w.AccountNumber(scope, string(mainAccount))
	if err != nil {
		return nil, err
	}

	utxos, err := w.UnspentOutputs(wallet.OutputSelectionPolicy{
		Account:               accountNumber,
		RequiredConfirmations: 0,
	})
	if err != nil {
		return nil, err
	}

	filtered := make([]*wallet.TransactionOutput, 0, len(utxos))
	for _, utxo := range utxos {
		scriptClass, _, _, err := txscript.ExtractPkScriptAddrs(utxo.Output.PkScript, w.ChainParams())
		if err != nil {
			return nil, err
		}

		switch scope {
		case p2wpkhKeyScope:
			if scriptClass == txscript.WitnessV0PubKeyHashTy {
				filtered = append(filtered, utxo)
			}
		case p2trKeyScope:
			if scriptClass == txscript.WitnessV1TaprootTy {
				filtered = append(filtered, utxo)
			}
		}
	}
	return filtered, nil
}

func withChainSource(chainSource chain.Interface) WalletOption {
	return func(s *service) error {
		if s.chainSource != nil {
			return fmt.Errorf("chain source already set")
		}

		if err := chainSource.Start(); err != nil {
			return fmt.Errorf("failed to start chain source: %s", err)
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

func withExtraAPI(api extraChainAPI) WalletOption {
	return func(s *service) error {
		if s.extraAPI != nil {
			return fmt.Errorf("extra chain API already set")
		}
		s.extraAPI = api
		return nil
	}
}

func withFeeEstimator(estimator chainfee.Estimator) WalletOption {
	return func(s *service) error {
		if s.feeEstimator != nil {
			return fmt.Errorf("fee estimator already set")
		}

		if err := estimator.Start(); err != nil {
			return fmt.Errorf("failed to start fee estimator: %s", err)
		}

		s.feeEstimator = estimator
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
	logger := btclog.NewBackend(log.StandardLogger().Writer()).Logger(subsystem)
	logger.SetLevel(btclog.LevelWarn)
	return logger
}
