package covenant

import (
	"fmt"
	"math"
	"time"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/ark/client/interfaces"
	"github.com/ark-network/ark/client/utils"
	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/tree"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/urfave/cli/v2"
	"github.com/vulpemventures/go-elements/address"
	"github.com/vulpemventures/go-elements/payment"
	"github.com/vulpemventures/go-elements/psetv2"
)

const dust = 450

type covenantLiquidCLI struct{}

func (c *covenantLiquidCLI) SendAsync(ctx *cli.Context) error {
	return fmt.Errorf("not implemented")
}

func (c *covenantLiquidCLI) Receive(ctx *cli.Context) error {
	offchainAddr, onboardingAddr, _, err := getAddress(ctx)
	if err != nil {
		return err
	}

	return utils.PrintJSON(map[string]interface{}{
		"offchain_address":   offchainAddr,
		"onboarding_address": onboardingAddr,
	})
}

func (c *covenantLiquidCLI) Redeem(ctx *cli.Context) error {
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
	return &covenantLiquidCLI{}
}

type receiver struct {
	To     string `json:"to"`
	Amount uint64 `json:"amount"`
}

func (r *receiver) isOnchain() bool {
	_, err := address.ToOutputScript(r.To)
	return err == nil
}

func sendOnchain(ctx *cli.Context, receivers []receiver) (string, error) {
	pset, err := psetv2.New(nil, nil, nil)
	if err != nil {
		return "", err
	}
	updater, err := psetv2.NewUpdater(pset)
	if err != nil {
		return "", err
	}

	net, err := utils.GetNetwork(ctx)
	if err != nil {
		return "", err
	}

	liquidNet := toElementsNetwork(net)

	targetAmount := uint64(0)
	for _, receiver := range receivers {
		targetAmount += receiver.Amount
		if receiver.Amount < dust {
			return "", fmt.Errorf("invalid amount (%d), must be greater than dust %d", receiver.Amount, dust)
		}

		script, err := address.ToOutputScript(receiver.To)
		if err != nil {
			return "", err
		}

		if err := updater.AddOutputs([]psetv2.OutputArgs{
			{
				Asset:  liquidNet.AssetID,
				Amount: receiver.Amount,
				Script: script,
			},
		}); err != nil {
			return "", err
		}
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

		changeScript, err := address.ToOutputScript(changeAddr)
		if err != nil {
			return "", err
		}

		if err := updater.AddOutputs([]psetv2.OutputArgs{
			{
				Asset:  liquidNet.AssetID,
				Amount: change,
				Script: changeScript,
			},
		}); err != nil {
			return "", err
		}
	}

	utx, err := pset.UnsignedTx()
	if err != nil {
		return "", err
	}

	vBytes := utx.VirtualSize()
	feeAmount := uint64(math.Ceil(float64(vBytes) * 0.5))

	if change > feeAmount {
		updater.Pset.Outputs[len(updater.Pset.Outputs)-1].Value = change - feeAmount
	} else if change == feeAmount {
		updater.Pset.Outputs = updater.Pset.Outputs[:len(updater.Pset.Outputs)-1]
	} else { // change < feeAmount
		if change > 0 {
			updater.Pset.Outputs = updater.Pset.Outputs[:len(updater.Pset.Outputs)-1]
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

			changeScript, err := address.ToOutputScript(changeAddr)
			if err != nil {
				return "", err
			}

			if err := updater.AddOutputs([]psetv2.OutputArgs{
				{
					Asset:  liquidNet.AssetID,
					Amount: newChange,
					Script: changeScript,
				},
			}); err != nil {
				return "", err
			}
		}
	}

	if err := updater.AddOutputs([]psetv2.OutputArgs{
		{
			Asset:  liquidNet.AssetID,
			Amount: feeAmount,
		},
	}); err != nil {
		return "", err
	}

	prvKey, err := utils.PrivateKeyFromPassword(ctx)
	if err != nil {
		return "", err
	}

	if err := signPset(ctx, updater.Pset, explorer, prvKey); err != nil {
		return "", err
	}

	if err := psetv2.FinalizeAll(updater.Pset); err != nil {
		return "", err
	}

	return updater.Pset.ToBase64()
}

func coinSelectOnchain(
	ctx *cli.Context,
	explorer utils.Explorer, targetAmount uint64, exclude []utils.Utxo,
) ([]utils.Utxo, uint64, error) {
	_, onboardingAddr, redemptionAddr, err := getAddress(ctx)
	if err != nil {
		return nil, 0, err
	}

	onboardingUtxoFromExplorer, err := explorer.GetUtxos(onboardingAddr)
	if err != nil {
		return nil, 0, err
	}

	utxos := make([]utils.Utxo, 0)
	selectedAmount := uint64(0)
	now := time.Now()

	onboardingExitDelay, err := utils.GetOnboardingExitDelay(ctx)
	if err != nil {
		return nil, 0, err
	}

	for _, utxo := range onboardingUtxoFromExplorer {
		if selectedAmount >= targetAmount {
			break
		}

		for _, excluded := range exclude {
			if utxo.Txid == excluded.Txid && utxo.Vout == excluded.Vout {
				continue
			}
		}

		utxo := utils.NewUtxo(utxo, uint(onboardingExitDelay))

		if utxo.SpendableAt.After(now) {
			utxos = append(utxos, utxo)
			selectedAmount += utxo.Amount
		}
	}

	if selectedAmount >= targetAmount {
		return utxos, selectedAmount - targetAmount, nil
	}

	redemptionUtxosFromExplorer, err := explorer.GetUtxos(redemptionAddr)
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
	updater *psetv2.Updater,
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
		sequence, err := utxo.Sequence()
		if err != nil {
			return err
		}

		if err := updater.AddInputs([]psetv2.InputArgs{
			{
				Txid:     utxo.Txid,
				TxIndex:  utxo.Vout,
				Sequence: sequence,
			},
		}); err != nil {
			return err
		}

		_, leafProof, err := computeVtxoTaprootScript(
			userPubkey, aspPubkey, utxo.Delay,
		)
		if err != nil {
			return err
		}

		inputIndex := len(updater.Pset.Inputs) - 1

		if err := updater.AddInTapLeafScript(inputIndex, psetv2.NewTapLeafScript(*leafProof, tree.UnspendableKey())); err != nil {
			return err
		}
	}

	return nil
}

func isOnchainOnly(receivers []*arkv1.Output) bool {
	for _, receiver := range receivers {
		isOnChain, _, _, err := decodeReceiverAddress(receiver.Address)
		if err != nil {
			continue
		}

		if !isOnChain {
			return false
		}
	}

	return true
}

func decodeReceiverAddress(addr string) (
	bool, []byte, *secp256k1.PublicKey, error,
) {
	outputScript, err := address.ToOutputScript(addr)
	if err != nil {
		_, userPubkey, _, err := common.DecodeAddress(addr)
		if err != nil {
			return false, nil, nil, err
		}
		return false, nil, userPubkey, nil
	}

	return true, outputScript, nil, nil
}

func getAddress(ctx *cli.Context) (offchainAddr, onboardingAddr, redemptionAddr string, err error) {
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

	onboardingExitDelay, err := utils.GetOnboardingExitDelay(ctx)
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

	liquidNet := toElementsNetwork(arkNet)

	vtxoTapKey, _, err := computeVtxoTaprootScript(
		userPubkey, aspPubkey, uint(unilateralExitDelay),
	)
	if err != nil {
		return
	}

	redemptionPay, err := payment.FromTweakedKey(vtxoTapKey, &liquidNet, nil)
	if err != nil {
		return
	}

	redemptionAddr, err = redemptionPay.TaprootAddress()
	if err != nil {
		return
	}

	onboardingTapKey, _, err := computeVtxoTaprootScript(
		userPubkey, aspPubkey, uint(onboardingExitDelay),
	)
	if err != nil {
		return
	}

	onboardingPay, err := payment.FromTweakedKey(onboardingTapKey, &liquidNet, nil)
	if err != nil {
		return
	}

	onboardingAddr, err = onboardingPay.TaprootAddress()
	if err != nil {
		return
	}

	offchainAddr = arkAddr

	return
}
