package covenantless

import (
	"fmt"
	"math"
	"time"

	"github.com/ark-network/ark/client/interfaces"
	"github.com/ark-network/ark/client/utils"
	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/bitcointree"
	"github.com/ark-network/ark/common/descriptor"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/urfave/cli/v2"
)

const dust = 450

type clArkBitcoinCLI struct{}

func (c *clArkBitcoinCLI) Receive(ctx *cli.Context) error {
	offchainAddr, boardingAddr, _, err := getAddress(ctx)
	if err != nil {
		return err
	}

	return utils.PrintJSON(map[string]interface{}{
		"offchain_address": offchainAddr,
		"boarding_address": boardingAddr.EncodeAddress(),
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

func (c *clArkBitcoinCLI) Send(ctx *cli.Context) error {
	return fmt.Errorf("not implemented")
}

type receiver struct {
	To     string `json:"to"`
	Amount uint64 `json:"amount"`
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

	utxos, change, err := coinSelectOnchain(
		ctx, explorer, targetAmount, nil,
	)
	if err != nil {
		return "", err
	}

	if err := addInputs(ctx, updater, utxos); err != nil {
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

	feeAmount := uint64(math.Ceil(float64(size)*feeRate) + 50)

	if change > feeAmount {
		updater.Upsbt.UnsignedTx.TxOut[len(updater.Upsbt.Outputs)-1].Value = int64(change - feeAmount)
	} else if change == feeAmount {
		updater.Upsbt.UnsignedTx.TxOut = updater.Upsbt.UnsignedTx.TxOut[:len(updater.Upsbt.UnsignedTx.TxOut)-1]
	} else { // change < feeAmount
		if change > 0 {
			updater.Upsbt.UnsignedTx.TxOut = updater.Upsbt.UnsignedTx.TxOut[:len(updater.Upsbt.UnsignedTx.TxOut)-1]
		}
		// reselect the difference
		selected, newChange, err := coinSelectOnchain(
			ctx, explorer, feeAmount-change, utxos,
		)
		if err != nil {
			return "", err
		}

		if err := addInputs(ctx, updater, selected); err != nil {
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
) ([]utils.Utxo, uint64, error) {
	_, boardingAddr, redemptionAddr, err := getAddress(ctx)
	if err != nil {
		return nil, 0, err
	}

	boardingUtxosFromExplorer, err := explorer.GetUtxos(boardingAddr.EncodeAddress())
	if err != nil {
		return nil, 0, err
	}

	utxos := make([]utils.Utxo, 0)
	selectedAmount := uint64(0)
	now := time.Now()

	boardingDescriptor, err := utils.GetBoardingDescriptor(ctx)
	if err != nil {
		return nil, 0, err
	}

	desc, err := descriptor.ParseTaprootDescriptor(boardingDescriptor)
	if err != nil {
		return nil, 0, err
	}

	_, timeoutBoarding, err := descriptor.ParseBoardingDescriptor(*desc)
	if err != nil {
		return nil, 0, err
	}

	for _, utxo := range boardingUtxosFromExplorer {
		if selectedAmount >= targetAmount {
			break
		}

		for _, excluded := range exclude {
			if utxo.Txid == excluded.Txid && utxo.Vout == excluded.Vout {
				continue
			}
		}

		utxo := utils.NewUtxo(utxo, uint(timeoutBoarding))

		if utxo.SpendableAt.After(now) {
			utxos = append(utxos, utxo)
			selectedAmount += utxo.Amount
		}
	}

	if selectedAmount >= targetAmount {
		return utxos, selectedAmount - targetAmount, nil
	}

	redemptionUtxosFromExplorer, err := explorer.GetUtxos(redemptionAddr.EncodeAddress())
	if err != nil {
		return nil, 0, err
	}

	vtxoExitDelay, err := utils.GetUnilateralExitDelay(ctx)
	if err != nil {
		return nil, 0, err
	}

	for _, utxo := range redemptionUtxosFromExplorer {
		if selectedAmount >= targetAmount {
			break
		}

		for _, excluded := range exclude {
			if utxo.Txid == excluded.Txid && utxo.Vout == excluded.Vout {
				continue
			}
		}

		utxo := utils.NewUtxo(utxo, uint(vtxoExitDelay))

		if utxo.SpendableAt.After(now) {
			utxos = append(utxos, utxo)
			selectedAmount += utxo.Amount
		}
	}

	if selectedAmount < targetAmount {
		return nil, 0, fmt.Errorf(
			"not enough funds to cover amount %d", targetAmount,
		)
	}

	return utxos, selectedAmount - targetAmount, nil
}

func addInputs(
	ctx *cli.Context,
	updater *psbt.Updater,
	utxos []utils.Utxo,
) error {
	userPubkey, err := utils.GetWalletPublicKey(ctx)
	if err != nil {
		return err
	}

	aspPubkey, err := utils.GetAspPublicKey(ctx)
	if err != nil {
		return err
	}

	for _, utxo := range utxos {
		previousHash, err := chainhash.NewHashFromStr(utxo.Txid)
		if err != nil {
			return err
		}

		sequence, err := utxo.Sequence()
		if err != nil {
			return err
		}

		updater.Upsbt.UnsignedTx.AddTxIn(&wire.TxIn{
			PreviousOutPoint: wire.OutPoint{
				Hash:  *previousHash,
				Index: utxo.Vout,
			},
			Sequence: sequence,
		})

		_, leafProof, err := computeVtxoTaprootScript(
			userPubkey, aspPubkey, utxo.Delay,
		)
		if err != nil {
			return err
		}

		controlBlock := leafProof.ToControlBlock(bitcointree.UnspendableKey())
		controlBlockBytes, err := controlBlock.ToBytes()
		if err != nil {
			return err
		}

		updater.Upsbt.Inputs = append(updater.Upsbt.Inputs, psbt.PInput{
			TaprootLeafScript: []*psbt.TaprootTapLeafScript{
				{
					ControlBlock: controlBlockBytes,
					Script:       leafProof.Script,
					LeafVersion:  leafProof.LeafVersion,
				},
			},
		})
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

func getAddress(ctx *cli.Context) (offchainAddr string, boardingAddr, redemptionAddr btcutil.Address, err error) {
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

	boardingDescriptor, err := utils.GetBoardingDescriptor(ctx)
	if err != nil {
		return
	}

	desc, err := descriptor.ParseTaprootDescriptor(boardingDescriptor)
	if err != nil {
		return
	}

	_, timeoutBoarding, err := descriptor.ParseBoardingDescriptor(*desc)
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

	vtxoTapKey, _, err := computeVtxoTaprootScript(
		userPubkey, aspPubkey, uint(unilateralExitDelay),
	)
	if err != nil {
		return
	}

	redemptionP2TR, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(vtxoTapKey),
		&netParams,
	)
	if err != nil {
		return
	}

	boardingTapKey, _, err := computeVtxoTaprootScript(
		userPubkey, aspPubkey, uint(timeoutBoarding),
	)
	if err != nil {
		return
	}

	boardingP2TR, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(boardingTapKey),
		&netParams,
	)

	redemptionAddr = redemptionP2TR
	boardingAddr = boardingP2TR
	offchainAddr = arkAddr

	return
}
