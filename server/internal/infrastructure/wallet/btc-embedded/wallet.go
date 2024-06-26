package btcwallet

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

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
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/sirupsen/logrus"
)

type accountName string

const (
	mainAccount      accountName = "main"
	connectorAccount accountName = "connector"
)

var (
	keyScope           = waddrmgr.KeyScopeBIP0044
	outputLockDuration = time.Minute
)

type WalletConfig struct {
	Datadir         string
	PublicPassword  []byte
	PrivatePassword []byte
	ChainParams     *chaincfg.Params
	ChainSource     chain.Interface
}

type service struct {
	loader   *wallet.Loader
	accounts map[accountName]uint32
	cfg      WalletConfig
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

	w, isLoaded := loader.LoadedWallet()
	if !isLoaded {
		return nil, errors.New("wallet not loaded")
	}

	w.SynchronizeRPC(cfg.ChainSource)

	return &service{loader, accounts, cfg}, nil
}

func (s *service) Close() {
	if err := s.loader.UnloadWallet(); err != nil {
		logrus.Errorf("error while unloading wallet: %s", err)
	}

	// TODO stop outside ?
	s.cfg.ChainSource.Stop()
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

func (s *service) EstimateFees(ctx context.Context, pset string) (uint64, error) {
	panic("unimplemented")
}

// TODO Scanner

// WatchScripts implements ports.WalletService.
func (s *service) WatchScripts(ctx context.Context, scripts []string) error {
	panic("unimplemented")
}

// UnwatchScripts implements ports.WalletService.
func (s *service) UnwatchScripts(ctx context.Context, scripts []string) error {
	panic("unimplemented")
}

// GetNotificationChannel implements ports.WalletService.
func (s *service) GetNotificationChannel(ctx context.Context) <-chan map[string]ports.VtxoWithValue {
	panic("unimplemented")
}

func (s *service) IsTransactionConfirmed(ctx context.Context, txid string) (isConfirmed bool, blocktime int64, err error) {
	panic("unimplemented")
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

func (s status) IsInitialized() bool {
	return s.initialized
}

func (s status) IsUnlocked() bool {
	return s.unlocked
}

func (s status) IsSynced() bool {
	return s.synced
}
