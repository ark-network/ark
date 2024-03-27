package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/urfave/cli/v2"
	"github.com/vulpemventures/go-elements/address"
)

var (
	addressFlag = cli.StringFlag{
		Name:     "address",
		Usage:    "main chain address receiving the redeeemed VTXO",
		Value:    "",
		Required: false,
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
	Usage:  "Redeem your offchain funds, either collaboratively or unilaterally",
	Flags:  []cli.Flag{&addressFlag, &amountToRedeemFlag, &forceFlag, &enableExpiryCoinselectFlag},
	Action: redeemAction,
}

func redeemAction(ctx *cli.Context) error {
	addr := ctx.String("address")
	amount := ctx.Uint64("amount")
	force := ctx.Bool("force")

	if len(addr) <= 0 && !force {
		return fmt.Errorf("missing address flag (--address)")
	}

	if !force && amount <= 0 {
		return fmt.Errorf("missing amount flag (--amount)")
	}

	client, clean, err := getClientFromState()
	if err != nil {
		return err
	}
	defer clean()

	if force {
		if amount > 0 {
			fmt.Printf("WARNING: unilateral exit (--force) ignores --amount flag, it will redeem all your VTXOs\n")
		}

		return unilateralRedeem(ctx.Context, client)
	}

	return collaborativeRedeem(ctx, client, addr, amount)
}

func collaborativeRedeem(
	ctx *cli.Context, client arkv1.ArkServiceClient, addr string, amount uint64,
) error {
	withExpiryCoinselect := ctx.Bool("enable-expiry-coinselect")

	if _, err := address.ToOutputScript(addr); err != nil {
		return fmt.Errorf("invalid onchain address")
	}

	net, err := address.NetworkForAddress(addr)
	if err != nil {
		return fmt.Errorf("invalid onchain address: unknown network")
	}
	_, liquidNet := getNetwork()
	if net.Name != liquidNet.Name {
		return fmt.Errorf("invalid onchain address: must be for %s network", liquidNet.Name)
	}

	if isConf, _ := address.IsConfidential(addr); isConf {
		info, _ := address.FromConfidential(addr)
		addr = info.Address
	}

	offchainAddr, _, _, err := getAddress()
	if err != nil {
		return err
	}

	receivers := []*arkv1.Output{
		{
			Address: addr,
			Amount:  amount,
		},
	}

	explorer := NewExplorer()

	vtxos, err := getVtxos(ctx.Context, explorer, client, offchainAddr, withExpiryCoinselect)
	if err != nil {
		return err
	}

	selectedCoins, changeAmount, err := coinSelect(vtxos, amount, withExpiryCoinselect)
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
		ctx.Context,
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

func unilateralRedeem(ctx context.Context, client arkv1.ArkServiceClient) error {
	offchainAddr, _, _, err := getAddress()
	if err != nil {
		return err
	}

	explorer := NewExplorer()
	vtxos, err := getVtxos(ctx, explorer, client, offchainAddr, false)
	if err != nil {
		return err
	}

	totalVtxosAmount := uint64(0)

	for _, vtxo := range vtxos {
		totalVtxosAmount += vtxo.amount
	}

	ok := askForConfirmation(fmt.Sprintf("redeem %d sats ?", totalVtxosAmount))
	if !ok {
		return fmt.Errorf("aborting unilateral exit")
	}

	// transactionsMap avoid duplicates
	transactionsMap := make(map[string]struct{}, 0)
	transactions := make([]string, 0)

	redeemBranches, err := getRedeemBranches(ctx, explorer, client, vtxos)
	if err != nil {
		return err
	}

	for _, branch := range redeemBranches {
		branchTxs, err := branch.redeemPath()
		if err != nil {
			return err
		}

		for _, txHex := range branchTxs {
			if _, ok := transactionsMap[txHex]; !ok {
				transactions = append(transactions, txHex)
				transactionsMap[txHex] = struct{}{}
			}
		}
	}

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
