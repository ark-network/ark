package covenantless

import (
	"fmt"
	"math"
	"time"

	"github.com/ark-network/ark-cli/interfaces"
	"github.com/ark-network/ark-cli/utils"
	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/bitcointree"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/urfave/cli/v2"
)

const dust = 450

type clArkBitcoinCLI struct{}

func (c *clArkBitcoinCLI) Receive(ctx *cli.Context) error {
	offchainAddr, onchainAddr, _, err := getAddress(ctx)
	if err != nil {
		return err
	}

	return utils.PrintJSON(map[string]interface{}{
		"offchain_address": offchainAddr,
		"onchain_address":  onchainAddr.EncodeAddress(),
	})
}

func (c *clArkBitcoinCLI) Redeem(ctx *cli.Context) error {
	addr := ctx.String("address")
	amount := ctx.Uint64("amount")
	force := ctx.Bool("force")

	if len(addr) <= 0 && !force {
		return fmt.Errorf("missing address flag (--address)")
	}

	if !force && amount <= 0 {
		return fmt.Errorf("missing amount flag (--amount)")
	}

	client, clean, err := getClientFromState(ctx)
	if err != nil {
		return err
	}
	defer clean()

	if force {
		if amount > 0 {
			fmt.Printf("WARNING: unilateral exit (--force) ignores --amount flag, it will redeem all your VTXOs\n")
		}

		return unilateralRedeem(ctx, client)
	}

	return collaborativeRedeem(ctx, client, addr, amount)
}

func New() interfaces.CLI {
	return &clArkBitcoinCLI{}
}

type receiver struct {
	To     string `json:"to"`
	Amount uint64 `json:"amount"`
}

func (r *receiver) isOnchain() bool {
	_, err := btcutil.DecodeAddress(r.To, nil)
	return err == nil
}

func sendOnchain(ctx *cli.Context, receivers []receiver) (string, error) {
	ptx, err := psbt.New(nil, nil, 2, 0, nil)
	if err != nil {
		return "", err
	}

	updater, err := psbt.NewUpdater(ptx)
	if err != nil {
		return "", err
	}

	net, err := utils.GetNetwork(ctx)
	if err != nil {
		return "", err
	}

	netParams := toChainParams(net)

	targetAmount := uint64(0)
	for _, receiver := range receivers {
		targetAmount += receiver.Amount
		if receiver.Amount < dust {
			return "", fmt.Errorf("invalid amount (%d), must be greater than dust %d", receiver.Amount, dust)
		}

		rcvAddr, err := btcutil.DecodeAddress(receiver.To, &netParams)
		if err != nil {
			return "", err
		}

		pkscript, err := txscript.PayToAddrScript(rcvAddr)
		if err != nil {
			return "", err
		}

		updater.Upsbt.UnsignedTx.AddTxOut(&wire.TxOut{
			Value:    int64(receiver.Amount),
			PkScript: pkscript,
		})
		updater.Upsbt.Outputs = append(updater.Upsbt.Outputs, psbt.POutput{})
	}

	explorer := utils.NewExplorer(ctx)

	utxos, delayedUtxos, change, err := coinSelectOnchain(
		ctx, explorer, targetAmount, nil,
	)
	if err != nil {
		return "", err
	}

	if err := addInputs(ctx, updater, utxos, delayedUtxos, &netParams); err != nil {
		return "", err
	}

	if change > 0 {
		_, changeAddr, _, err := getAddress(ctx)
		if err != nil {
			return "", err
		}

		pkscript, err := txscript.PayToAddrScript(changeAddr)
		if err != nil {
			return "", err
		}

		updater.Upsbt.UnsignedTx.AddTxOut(&wire.TxOut{
			Value:    int64(change),
			PkScript: pkscript,
		})
		updater.Upsbt.Outputs = append(updater.Upsbt.Outputs, psbt.POutput{})
	}

	size := updater.Upsbt.UnsignedTx.SerializeSize()
	feeRate, err := explorer.GetFeeRate()
	if err != nil {
		return "", err
	}

	feeAmount := uint64(math.Ceil(float64(size) * feeRate))

	if change > feeAmount {
		updater.Upsbt.UnsignedTx.TxOut[len(updater.Upsbt.Outputs)-1].Value = int64(change - feeAmount)
	} else if change == feeAmount {
		updater.Upsbt.UnsignedTx.TxOut = updater.Upsbt.UnsignedTx.TxOut[:len(updater.Upsbt.UnsignedTx.TxOut)-1]
	} else { // change < feeAmount
		if change > 0 {
			updater.Upsbt.UnsignedTx.TxOut = updater.Upsbt.UnsignedTx.TxOut[:len(updater.Upsbt.UnsignedTx.TxOut)-1]
		}
		// reselect the difference
		selected, delayedSelected, newChange, err := coinSelectOnchain(
			ctx, explorer, feeAmount-change, append(utxos, delayedUtxos...),
		)
		if err != nil {
			return "", err
		}

		if err := addInputs(ctx, updater, selected, delayedSelected, &netParams); err != nil {
			return "", err
		}

		if newChange > 0 {
			_, changeAddr, _, err := getAddress(ctx)
			if err != nil {
				return "", err
			}

			pkscript, err := txscript.PayToAddrScript(changeAddr)
			if err != nil {
				return "", err
			}

			updater.Upsbt.UnsignedTx.AddTxOut(&wire.TxOut{
				Value:    int64(newChange),
				PkScript: pkscript,
			})
			updater.Upsbt.Outputs = append(updater.Upsbt.Outputs, psbt.POutput{})
		}
	}

	prvKey, err := utils.PrivateKeyFromPassword(ctx)
	if err != nil {
		return "", err
	}

	if err := signPsbt(ctx, updater.Upsbt, explorer, prvKey); err != nil {
		return "", err
	}

	for i := range updater.Upsbt.Inputs {
		if err := psbt.Finalize(updater.Upsbt, i); err != nil {
			return "", err
		}
	}

	return updater.Upsbt.B64Encode()
}

func coinSelectOnchain(
	ctx *cli.Context,
	explorer utils.Explorer, targetAmount uint64, exclude []utils.Utxo,
) ([]utils.Utxo, []utils.Utxo, uint64, error) {
	_, onchainAddr, _, err := getAddress(ctx)
	if err != nil {
		return nil, nil, 0, err
	}

	fromExplorer, err := explorer.GetUtxos(onchainAddr.EncodeAddress())
	if err != nil {
		return nil, nil, 0, err
	}

	utxos := make([]utils.Utxo, 0)
	selectedAmount := uint64(0)
	for _, utxo := range fromExplorer {
		if selectedAmount >= targetAmount {
			break
		}

		for _, excluded := range exclude {
			if utxo.Txid == excluded.Txid && utxo.Vout == excluded.Vout {
				continue
			}
		}

		utxos = append(utxos, utxo)
		selectedAmount += utxo.Amount
	}

	if selectedAmount >= targetAmount {
		return utxos, nil, selectedAmount - targetAmount, nil
	}

	userPubkey, err := utils.GetWalletPublicKey(ctx)
	if err != nil {
		return nil, nil, 0, err
	}

	aspPubkey, err := utils.GetAspPublicKey(ctx)
	if err != nil {
		return nil, nil, 0, err
	}

	unilateralExitDelay, err := utils.GetUnilateralExitDelay(ctx)
	if err != nil {
		return nil, nil, 0, err
	}

	vtxoTapKey, _, err := computeVtxoTaprootScript(
		userPubkey, aspPubkey, uint(unilateralExitDelay),
	)
	if err != nil {
		return nil, nil, 0, err
	}

	net, err := utils.GetNetwork(ctx)
	if err != nil {
		return nil, nil, 0, err
	}

	liquidNet := toChainParams(net)

	p2tr, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(vtxoTapKey),
		&liquidNet,
	)
	if err != nil {
		return nil, nil, 0, err
	}

	addr := p2tr.EncodeAddress()

	fromExplorer, err = explorer.GetUtxos(addr)
	if err != nil {
		return nil, nil, 0, err
	}

	delayedUtxos := make([]utils.Utxo, 0)
	for _, utxo := range fromExplorer {
		if selectedAmount >= targetAmount {
			break
		}

		availableAt := time.Unix(utxo.Status.Blocktime, 0).Add(
			time.Duration(unilateralExitDelay) * time.Second,
		)
		if availableAt.After(time.Now()) {
			continue
		}

		for _, excluded := range exclude {
			if utxo.Txid == excluded.Txid && utxo.Vout == excluded.Vout {
				continue
			}
		}

		delayedUtxos = append(delayedUtxos, utxo)
		selectedAmount += utxo.Amount
	}

	if selectedAmount < targetAmount {
		return nil, nil, 0, fmt.Errorf(
			"not enough funds to cover amount %d", targetAmount,
		)
	}

	return utxos, delayedUtxos, selectedAmount - targetAmount, nil
}

func addInputs(
	ctx *cli.Context,
	updater *psbt.Updater,
	utxos, delayedUtxos []utils.Utxo,
	net *chaincfg.Params,
) error {
	_, onchainAddr, _, err := getAddress(ctx)
	if err != nil {
		return err
	}

	changeScript, err := txscript.PayToAddrScript(onchainAddr)
	if err != nil {
		return err
	}

	for _, utxo := range utxos {
		previousHash, err := chainhash.NewHashFromStr(utxo.Txid)
		if err != nil {
			return err
		}

		updater.Upsbt.UnsignedTx.AddTxIn(&wire.TxIn{
			PreviousOutPoint: wire.OutPoint{
				Hash:  *previousHash,
				Index: utxo.Vout,
			},
		})

		updater.Upsbt.Inputs = append(updater.Upsbt.Inputs, psbt.PInput{})

		if err := updater.AddInWitnessUtxo(
			&wire.TxOut{
				Value:    int64(utxo.Amount),
				PkScript: changeScript,
			},
			len(updater.Upsbt.UnsignedTx.TxIn)-1,
		); err != nil {
			return err
		}
	}

	if len(delayedUtxos) > 0 {
		userPubkey, err := utils.GetWalletPublicKey(ctx)
		if err != nil {
			return err
		}

		aspPubkey, err := utils.GetAspPublicKey(ctx)
		if err != nil {
			return err
		}

		unilateralExitDelay, err := utils.GetUnilateralExitDelay(ctx)
		if err != nil {
			return err
		}

		vtxoTapKey, leafProof, err := computeVtxoTaprootScript(
			userPubkey, aspPubkey, uint(unilateralExitDelay),
		)
		if err != nil {
			return err
		}

		p2tr, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(vtxoTapKey), net)
		if err != nil {
			return err
		}

		script, err := txscript.PayToAddrScript(p2tr)
		if err != nil {
			return err
		}

		for _, utxo := range delayedUtxos {
			previousHash, err := chainhash.NewHashFromStr(utxo.Txid)
			if err != nil {
				return err
			}

			if err := addVtxoInput(
				updater,
				&wire.OutPoint{
					Hash:  *previousHash,
					Index: utxo.Vout,
				},
				uint(unilateralExitDelay),
				leafProof,
			); err != nil {
				return err
			}

			if err := updater.AddInWitnessUtxo(
				&wire.TxOut{
					Value:    int64(utxo.Amount),
					PkScript: script,
				},
				len(updater.Upsbt.Inputs)-1,
			); err != nil {
				return err
			}
		}
	}

	return nil
}

func decodeReceiverAddress(addr string) (
	bool, []byte, *secp256k1.PublicKey, error,
) {
	decoded, err := btcutil.DecodeAddress(addr, nil)
	if err != nil {
		_, userPubkey, _, err := common.DecodeAddress(addr)
		if err != nil {
			return false, nil, nil, err
		}
		return false, nil, userPubkey, nil
	}

	pkscript, err := txscript.PayToAddrScript(decoded)
	if err != nil {
		return false, nil, nil, err
	}

	return true, pkscript, nil, nil
}

func addVtxoInput(
	updater *psbt.Updater, inputArgs *wire.OutPoint, exitDelay uint,
	tapLeafProof *txscript.TapscriptProof,
) error {
	sequence, err := common.BIP68EncodeAsNumber(exitDelay)
	if err != nil {
		return nil
	}

	nextInputIndex := len(updater.Upsbt.Inputs)
	updater.Upsbt.UnsignedTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: *inputArgs,
		Sequence:         sequence,
	})
	updater.Upsbt.Inputs = append(updater.Upsbt.Inputs, psbt.PInput{})

	controlBlock := tapLeafProof.ToControlBlock(bitcointree.UnspendableKey())
	controlBlockBytes, err := controlBlock.ToBytes()
	if err != nil {
		return err
	}

	updater.Upsbt.Inputs[nextInputIndex].TaprootLeafScript = []*psbt.TaprootTapLeafScript{
		{
			ControlBlock: controlBlockBytes,
			Script:       tapLeafProof.Script,
			LeafVersion:  tapLeafProof.LeafVersion,
		},
	}

	return nil
}

func getAddress(ctx *cli.Context) (offchainAddr string, onchainAddr, redemptionAddr btcutil.Address, err error) {
	userPubkey, err := utils.GetWalletPublicKey(ctx)
	if err != nil {
		return
	}

	aspPubkey, err := utils.GetAspPublicKey(ctx)
	if err != nil {
		return
	}

	unilateralExitDelay, err := utils.GetUnilateralExitDelay(ctx)
	if err != nil {
		return
	}

	arkNet, err := utils.GetNetwork(ctx)
	if err != nil {
		return
	}

	arkAddr, err := common.EncodeAddress(arkNet.Addr, userPubkey, aspPubkey)
	if err != nil {
		return
	}

	netParams := toChainParams(arkNet)

	p2wpkh, err := btcutil.NewAddressWitnessPubKeyHash(btcutil.Hash160(userPubkey.SerializeCompressed()), &netParams)
	if err != nil {
		return
	}

	vtxoTapKey, _, err := computeVtxoTaprootScript(
		userPubkey, aspPubkey, uint(unilateralExitDelay),
	)
	if err != nil {
		return
	}

	p2tr, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(vtxoTapKey),
		&netParams,
	)
	if err != nil {
		return
	}

	redemptionAddr = p2tr
	onchainAddr = p2wpkh
	offchainAddr = arkAddr

	return
}
