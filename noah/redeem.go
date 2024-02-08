package main

import (
	"bufio"
	"fmt"
	"log"
	"math"
	"os"
	"strings"
	"time"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/ark/common/tree"
	"github.com/urfave/cli/v2"
	"github.com/vulpemventures/go-elements/address"
	"github.com/vulpemventures/go-elements/psetv2"
)

var (
	addressFlag = cli.StringFlag{
		Name:     "address",
		Usage:    "main chain address receiving the redeeemed VTXO",
		Value:    "",
		Required: true,
	}

	amountToRedeemFlag = cli.Uint64Flag{
		Name:     "amount",
		Usage:    "amount to redeem",
		Value:    0,
		Required: false,
	}

	forceFlag = cli.BoolFlag{
		Name:     "force",
		Usage:    "force redemption without collaborate with the Ark service provider",
		Value:    false,
		Required: false,
	}
)

var redeemCommand = cli.Command{
	Name:   "redeem",
	Usage:  "Redeem VTXO(s) to onchain",
	Flags:  []cli.Flag{&addressFlag, &amountToRedeemFlag, &forceFlag},
	Action: redeemAction,
}

func redeemAction(ctx *cli.Context) error {
	addr := ctx.String("address")
	amount := ctx.Uint64("amount")
	force := ctx.Bool("force")

	if len(addr) <= 0 {
		return fmt.Errorf("missing address flag (--address)")
	}
	if _, err := address.ToOutputScript(addr); err != nil {
		return fmt.Errorf("invalid onchain address")
	}
	net, err := address.NetworkForAddress(addr)
	if err != nil {
		return fmt.Errorf("invalid onchain address: unknown network")
	}
	_, liquidNet, _ := getNetwork()
	if net.Name != liquidNet.Name {
		return fmt.Errorf("invalid onchain address: must be for %s network", liquidNet.Name)
	}

	if !force && amount <= 0 {
		return fmt.Errorf("missing amount flag (--amount)")
	}

	if force {
		if amount > 0 {
			fmt.Printf("WARNING: unilateral exit (--force) ignores --amount flag, it will redeem all your VTXOs\n")
		}

		return unilateralRedeem(ctx, addr)
	}

	return collaborativeRedeem(ctx, addr, amount)
}

func collaborativeRedeem(ctx *cli.Context, addr string, amount uint64) error {
	if isConf, _ := address.IsConfidential(addr); isConf {
		info, _ := address.FromConfidential(addr)
		addr = info.Address
	}

	offchainAddr, _, err := getAddress()
	if err != nil {
		return err
	}

	receivers := []*arkv1.Output{
		{
			Address: addr,
			Amount:  amount,
		},
	}

	client, close, err := getClientFromState(ctx)
	if err != nil {
		return err
	}
	defer close()

	vtxos, err := getVtxos(ctx, client, offchainAddr)
	if err != nil {
		return err
	}

	selectedCoins, changeAmount, err := coinSelect(vtxos, amount)
	if err != nil {
		return err
	}

	if changeAmount > 0 {
		receivers = append(receivers, &arkv1.Output{
			Address: offchainAddr,
			Amount:  changeAmount,
		})
	}

	inputs := make([]*arkv1.Input, 0, len(selectedCoins))

	for _, coin := range selectedCoins {
		inputs = append(inputs, &arkv1.Input{
			Txid: coin.txid,
			Vout: coin.vout,
		})
	}

	secKey, err := privateKeyFromPassword()
	if err != nil {
		return err
	}

	registerResponse, err := client.RegisterPayment(ctx.Context, &arkv1.RegisterPaymentRequest{
		Inputs: inputs,
	})
	if err != nil {
		return err
	}

	_, err = client.ClaimPayment(ctx.Context, &arkv1.ClaimPaymentRequest{
		Id:      registerResponse.GetId(),
		Outputs: receivers,
	})
	if err != nil {
		return err
	}

	poolTxID, err := handleRoundStream(
		ctx,
		client,
		registerResponse.GetId(),
		selectedCoins,
		secKey,
		receivers,
	)
	if err != nil {
		return err
	}

	if err := printJSON(map[string]interface{}{
		"pool_txid": poolTxID,
	}); err != nil {
		return err
	}

	return nil
}

func unilateralRedeem(ctx *cli.Context, addr string) error {
	onchainScript, err := address.ToOutputScript(addr)
	if err != nil {
		return err
	}

	client, close, err := getClientFromState(ctx)
	if err != nil {
		return err
	}
	defer close()

	offchainAddr, _, err := getAddress()
	if err != nil {
		return err
	}

	vtxos, err := getVtxos(ctx, client, offchainAddr)
	if err != nil {
		return err
	}

	totalVtxosAmount := uint64(0)

	for _, vtxo := range vtxos {
		totalVtxosAmount += vtxo.amount
	}

	ok := askForConfirmation(fmt.Sprintf("redeem %d sats to %s ?", totalVtxosAmount, addr))
	if !ok {
		return fmt.Errorf("aborting unilateral exit")
	}

	finalPset, err := psetv2.New(nil, nil, nil)
	if err != nil {
		return err
	}
	updater, err := psetv2.NewUpdater(finalPset)
	if err != nil {
		return err
	}

	congestionTrees := make(map[string]tree.CongestionTree, 0)
	transactionsMap := make(map[string]struct{}, 0)
	transactions := make([]string, 0)

	for _, vtxo := range vtxos {
		if _, ok := congestionTrees[vtxo.poolTxid]; !ok {
			round, err := client.GetRound(ctx.Context, &arkv1.GetRoundRequest{
				Txid: vtxo.poolTxid,
			})
			if err != nil {
				return err
			}

			treeFromRound := round.GetRound().GetCongestionTree()
			congestionTree, err := toCongestionTree(treeFromRound)
			if err != nil {
				return err
			}

			congestionTrees[vtxo.poolTxid] = congestionTree
		}

		redeemBranch, err := newRedeemBranch(ctx, congestionTrees[vtxo.poolTxid], vtxo)
		if err != nil {
			return err
		}

		if err := redeemBranch.UpdatePath(); err != nil {
			return err
		}

		branchTxs, err := redeemBranch.RedeemPath()
		if err != nil {
			return err
		}

		if err := redeemBranch.AddVtxoInput(updater); err != nil {
			return err
		}

		for _, txHex := range branchTxs {
			if _, ok := transactionsMap[txHex]; !ok {
				transactions = append(transactions, txHex)
				transactionsMap[txHex] = struct{}{}
			}
		}
	}

	_, net, err := getNetwork()
	if err != nil {
		return err
	}

	outputs := []psetv2.OutputArgs{
		{
			Asset:  net.AssetID,
			Amount: totalVtxosAmount,
			Script: onchainScript,
		},
	}

	if err := updater.AddOutputs(outputs); err != nil {
		return err
	}

	utx, err := updater.Pset.UnsignedTx()
	if err != nil {
		return err
	}

	vBytes := utx.VirtualSize()
	feeAmount := uint64(math.Ceil(float64(vBytes) * 0.25))

	if totalVtxosAmount-feeAmount <= 0 {
		return fmt.Errorf("not enough VTXOs to pay the fees (%d sats), aborting unilateral exit", feeAmount)
	}

	updater.Pset.Outputs[0].Value = totalVtxosAmount - feeAmount

	if err := updater.AddOutputs([]psetv2.OutputArgs{
		{
			Asset:  net.AssetID,
			Amount: feeAmount,
		},
	}); err != nil {
		return err
	}

	prvKey, err := privateKeyFromPassword()
	if err != nil {
		return err
	}

	explorer := NewExplorer()

	for i, txHex := range transactions {
		for {
			txid, err := explorer.Broadcast(txHex)
			if err != nil {
				if strings.Contains(strings.ToLower(err.Error()), "bad-txns-inputs-missingorspent") {
					time.Sleep(1 * time.Second)
				} else {
					return err
				}
			}

			if len(txid) > 0 {
				fmt.Printf("(%d/%d) broadcasted tx %s\n", i+1, len(transactions), txid)
				break
			}
		}
	}

	if err := signPset(finalPset, explorer, prvKey); err != nil {
		return err
	}

	for i, input := range finalPset.Inputs {
		if len(input.TapScriptSig) > 0 || len(input.PartialSigs) > 0 {
			if err := psetv2.Finalize(finalPset, i); err != nil {
				return err
			}
		}
	}

	signedTx, err := psetv2.Extract(finalPset)
	if err != nil {
		return err
	}

	hex, err := signedTx.ToHex()
	if err != nil {
		return err
	}

	for {
		id, err := explorer.Broadcast(hex)
		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "bad-txns-inputs-missingorspent") {
				time.Sleep(1 * time.Second)
				continue
			}
			return err
		}
		if id != "" {
			fmt.Printf("(final) redeem tx %s\n", id)
			break
		}
	}

	return nil
}

// askForConfirmation asks the user for confirmation. A user must type in "yes" or "no" and then press enter.
// if the input is not recognized, it will ask again.
func askForConfirmation(s string) bool {
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Printf("%s [y/n]: ", s)

		response, err := reader.ReadString('\n')
		if err != nil {
			log.Fatal(err)
		}

		response = strings.ToLower(strings.TrimSpace(response))

		if response == "y" || response == "yes" {
			return true
		} else if response == "n" || response == "no" {
			return false
		}
	}
}
