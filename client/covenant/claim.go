package covenant

import (
	"fmt"
	"time"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/ark/client/utils"
	"github.com/ark-network/ark/common/descriptor"
	"github.com/urfave/cli/v2"
)

func (c *covenantLiquidCLI) Claim(ctx *cli.Context) error {
	client, cancel, err := getClientFromState(ctx)
	if err != nil {
		return err
	}
	defer cancel()

	offchainAddr, boardingAddr, _, err := getAddress(ctx)
	if err != nil {
		return err
	}

	boardingDescriptor, err := utils.GetBoardingDescriptor(ctx)
	if err != nil {
		return err
	}

	desc, err := descriptor.ParseTaprootDescriptor(boardingDescriptor)
	if err != nil {
		return err
	}

	_, timeoutBoarding, err := descriptor.ParseBoardingDescriptor(*desc)
	if err != nil {
		return err
	}

	explorer := utils.NewExplorer(ctx)

	boardingUtxosFromExplorer, err := explorer.GetUtxos(boardingAddr)
	if err != nil {
		return err
	}

	now := time.Now()
	boardingUtxos := make([]utils.Utxo, 0, len(boardingUtxosFromExplorer))
	for _, utxo := range boardingUtxosFromExplorer {
		u := utils.NewUtxo(utxo, uint(timeoutBoarding))
		if u.SpendableAt.Before(now) {
			continue // cannot claim if onchain spendable
		}

		boardingUtxos = append(boardingUtxos, u)
	}

	var pendingBalance uint64

	for _, utxo := range boardingUtxos {
		pendingBalance += utxo.Amount
	}

	if pendingBalance == 0 {
		return fmt.Errorf("no boarding utxos to claim")
	}

	receiver := receiver{
		To:     offchainAddr,
		Amount: pendingBalance,
	}

	if len(ctx.String("password")) == 0 {
		if ok := askForConfirmation(
			fmt.Sprintf(
				"claim %d satoshis from %d boarding utxos",
				pendingBalance, len(boardingUtxos),
			),
		); !ok {
			return nil
		}
	}

	return selfTransferAllPendingPayments(
		ctx, client, boardingUtxos, receiver, boardingDescriptor,
	)
}

func selfTransferAllPendingPayments(
	ctx *cli.Context,
	client arkv1.ArkServiceClient,
	boardingUtxos []utils.Utxo,
	myself receiver,
	desc string,
) error {
	inputs := make([]*arkv1.Input, 0, len(boardingUtxos))

	for _, outpoint := range boardingUtxos {
		inputs = append(inputs, &arkv1.Input{
			Input: &arkv1.Input_BoardingInput{
				BoardingInput: &arkv1.BoardingInput{
					Txid:        outpoint.Txid,
					Vout:        outpoint.Vout,
					Descriptor_: desc,
				},
			},
		})
	}

	receiversOutput := []*arkv1.Output{
		{
			Address: myself.To,
			Amount:  myself.Amount,
		},
	}

	secKey, err := utils.PrivateKeyFromPassword(ctx)
	if err != nil {
		return err
	}

	registerResponse, err := client.RegisterPayment(
		ctx.Context, &arkv1.RegisterPaymentRequest{Inputs: inputs},
	)
	if err != nil {
		return err
	}

	_, err = client.ClaimPayment(ctx.Context, &arkv1.ClaimPaymentRequest{
		Id:      registerResponse.GetId(),
		Outputs: []*arkv1.Output{{Address: myself.To, Amount: myself.Amount}},
	})
	if err != nil {
		return err
	}

	poolTxID, err := handleRoundStream(
		ctx, client, registerResponse.GetId(), make([]vtxo, 0),
		len(boardingUtxos) > 0, secKey, receiversOutput,
	)
	if err != nil {
		return err
	}

	return utils.PrintJSON(map[string]interface{}{
		"pool_txid": poolTxID,
	})
}
