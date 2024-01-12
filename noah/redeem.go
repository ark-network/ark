package main

import (
	"fmt"
	"io"
	"time"

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
			fmt.Println("amount flag is forbidden when using --force")
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

	offchainAddr, onchainAddr, err := getAddress()
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

	selectedCoins, changeAmount, err := coinSelect(vtxos, uint64(totalVtxosAmount))
	if err != nil {
		return err
	}

	if changeAmount > 0 {
		return fmt.Errorf("unilateral redemption does not allow change, it will redeem all the selected VTXOs for a value of %d", totalVtxosAmount)
	}

	fmt.Printf("redeeming %d VTXOs for a value of %d sats\n", len(selectedCoins), totalVtxosAmount)

	totalAmount := uint64(0)

	finalPset, err := psetv2.New(nil, nil, nil)
	if err != nil {
		return err
	}
	updater, err := psetv2.NewUpdater(finalPset)
	if err != nil {
		return err
	}

	congestionTrees := make(map[string]*arkv1.Tree, 0)
	transactionsMap := make(map[string]struct{}, 0)
	transactions := make([]string, 0)

	for _, vtxo := range selectedCoins {
		if _, ok := congestionTrees[vtxo.poolTxid]; !ok {
			round, err := client.GetRound(ctx.Context, &arkv1.GetRoundRequest{
				Txid: vtxo.poolTxid,
			})
			if err != nil {
				return err
			}

			congestionTrees[vtxo.poolTxid] = round.GetRound().GetCongestionTree()
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

		totalAmount += vtxo.amount
	}

	_, net, err := getNetwork()
	if err != nil {
		return err
	}

	feeAmount := uint64(minRelayFee + 50*len(transactions))

	utxos, change, err := coinSelectOnchain(onchainAddr, feeAmount)
	if err != nil {
		return err
	}

	inputs := make([]psetv2.InputArgs, 0, len(utxos))
	for _, utxo := range utxos {
		inputs = append(inputs, psetv2.InputArgs{
			Txid:    utxo.Txid,
			TxIndex: utxo.Vout,
		})
	}

	if err := updater.AddInputs(inputs); err != nil {
		return err
	}

	outputs := make([]psetv2.OutputArgs, 0, len(utxos))

	outputs = append(outputs, psetv2.OutputArgs{
		Asset:  net.AssetID,
		Amount: totalAmount,
		Script: onchainScript,
	})

	if change > 0 {
		script, err := address.ToOutputScript(onchainAddr)
		if err != nil {
			return err
		}

		outputs = append(outputs, psetv2.OutputArgs{
			Asset:  net.AssetID,
			Amount: change,
			Script: script,
		})
	}

	outputs = append(outputs, psetv2.OutputArgs{
		Asset:  net.AssetID,
		Amount: feeAmount,
	})

	if err := updater.AddOutputs(outputs); err != nil {
		return err
	}

	prvKey, err := privateKeyFromPassword()
	if err != nil {
		return err
	}

	explorer := NewExplorer()

	for _, txHex := range transactions {
		txid, err := explorer.Broadcast(txHex)
		if err != nil {
			return err
		}
		time.Sleep(10 * time.Millisecond)

		fmt.Printf("(unilateral exit) broadcasted tx %s\n", txid)
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

	id, err := explorer.Broadcast(hex)
	if err != nil {
		return err
	}

	fmt.Printf("(unilateral exit) final redeem tx %s\n", id)

	return nil
}

func toInputArgs(utxos []utxo) []psetv2.InputArgs {
	inputs := make([]psetv2.InputArgs, 0, len(utxos))
	for _, utxo := range utxos {
		inputs = append(inputs, psetv2.InputArgs{
			Txid:    utxo.Txid,
			TxIndex: utxo.Vout,
		})
	}
	return inputs
}
