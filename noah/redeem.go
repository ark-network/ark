package main

import (
	"fmt"
	"io"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
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
	if isConf, _ := address.IsConfidential(addr); isConf {
		return fmt.Errorf("invalid onchain address: must be unconfidential")
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
		return unilateralRedeem(addr)
	}

	return collaborativeRedeem(ctx, addr, amount)
}

func collaborativeRedeem(ctx *cli.Context, address string, amount uint64) error {
	offchainAddr, _, err := getAddress()
	if err != nil {
		return err
	}

	receivers := []*arkv1.Output{
		{
			Address: address,
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

	stream, err := client.GetEventStream(ctx.Context, &arkv1.GetEventStreamRequest{})
	if err != nil {
		return err
	}

	var pingStop func()
	pingReq := &arkv1.PingRequest{
		PaymentId: registerResponse.GetId(),
	}
	for pingStop == nil {
		pingStop = ping(ctx, client, pingReq)
	}

	for {
		event, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		if event.GetRoundFailed() != nil {
			return fmt.Errorf("round failed: %s", event.GetRoundFailed().GetReason())
		}

		if event.GetRoundFinalization() != nil {
			// stop pinging as soon as we receive some forfeit txs
			pingStop()
			forfeits := event.GetRoundFinalization().GetForfeitTxs()
			signedForfeits := make([]string, 0)

			for _, forfeit := range forfeits {
				pset, err := psetv2.NewPsetFromBase64(forfeit)
				if err != nil {
					return err
				}

				// check if it contains one of the input to sign
				for _, input := range pset.Inputs {
					inputTxid := chainhash.Hash(input.PreviousTxid).String()

					for _, coin := range selectedCoins {
						if inputTxid == coin.txid {
							// TODO: sign the vtxo input
							signedForfeits = append(signedForfeits, forfeit)
						}
					}
				}
			}

			// if no forfeit txs have been signed, start pinging again and wait for the next round
			if len(signedForfeits) == 0 {
				pingStop = nil
				for pingStop == nil {
					pingStop = ping(ctx, client, pingReq)
				}
				continue
			}

			_, err := client.FinalizePayment(ctx.Context, &arkv1.FinalizePaymentRequest{
				SignedForfeitTxs: signedForfeits,
			})
			if err != nil {
				return err
			}

			continue
		}

		if event.GetRoundFinalized() != nil {
			return printJSON(map[string]interface{}{
				"pool_txid": event.GetRoundFinalized().GetPoolTxid(),
			})
		}
	}

	return nil
}

func unilateralRedeem(address string) error {
	fmt.Println("unilateral redeem is not implemented yet")
	return nil
}
