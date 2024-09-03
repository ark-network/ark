package covenantless

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/ark/client/utils"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/urfave/cli/v2"
)

func collaborativeRedeem(
	ctx *cli.Context, client arkv1.ArkServiceClient, addr string, amount uint64,
) error {
	withExpiryCoinselect := ctx.Bool("enable-expiry-coinselect")

	_, err := btcutil.DecodeAddress(addr, nil)
	if err != nil {
		return fmt.Errorf("invalid onchain address")
	}

	netinstate, err := utils.GetNetwork(ctx)
	if err != nil {
		return err
	}

	netParams := toChainParams(netinstate)

	if netinstate.Name != netParams.Name {
		return fmt.Errorf("invalid onchain address: must be for %s network", netParams.Name)
	}

	offchainAddr, _, _, err := getAddress(ctx)
	if err != nil {
		return err
	}

	receivers := []*arkv1.Output{
		{
			Address: addr,
			Amount:  amount,
		},
	}

	explorer := utils.NewExplorer(ctx)

	vtxos, err := getVtxos(ctx, explorer, client, offchainAddr, withExpiryCoinselect)
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
			Input: &arkv1.Input_VtxoInput{
				VtxoInput: &arkv1.VtxoInput{
					Txid: coin.txid,
					Vout: coin.vout,
				},
			},
		})
	}

	secKey, err := utils.PrivateKeyFromPassword(ctx)
	if err != nil {
		return err
	}

	ephemeralKey, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return err
	}

	pubkey := hex.EncodeToString(ephemeralKey.PubKey().SerializeCompressed())

	registerResponse, err := client.RegisterPayment(ctx.Context, &arkv1.RegisterPaymentRequest{
		Inputs:          inputs,
		EphemeralPubkey: &pubkey,
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
		false,
		secKey,
		receivers,
		ephemeralKey,
	)
	if err != nil {
		return err
	}

	return utils.PrintJSON(map[string]interface{}{
		"pool_txid": poolTxID,
	})
}

func unilateralRedeem(ctx *cli.Context, client arkv1.ArkServiceClient) error {
	offchainAddr, _, _, err := getAddress(ctx)
	if err != nil {
		return err
	}

	explorer := utils.NewExplorer(ctx)
	vtxos, err := getVtxos(ctx, explorer, client, offchainAddr, false)
	if err != nil {
		return err
	}

	totalVtxosAmount := uint64(0)

	for _, vtxo := range vtxos {
		totalVtxosAmount += vtxo.amount
	}

	if len(ctx.String("password")) == 0 {
		ok := askForConfirmation(fmt.Sprintf("redeem %d sats ?", totalVtxosAmount))
		if !ok {
			return fmt.Errorf("aborting unilateral exit")
		}
	}

	// transactionsMap avoid duplicates
	transactionsMap := make(map[string]struct{}, 0)
	transactions := make([]string, 0)

	redeemBranches, err := getRedeemBranches(ctx.Context, explorer, client, vtxos)
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
					fmt.Printf("error broadcasting tx %s: %s\n", txHex, err)
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
