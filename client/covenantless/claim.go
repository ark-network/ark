package covenantless

import (
	"encoding/hex"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/ark/client/utils"
	"github.com/urfave/cli/v2"
)

func (c *clArkBitcoinCLI) ClaimAsync(ctx *cli.Context) error {
	client, cancel, err := getClientFromState(ctx)
	if err != nil {
		return err
	}
	defer cancel()

	mypubkey, err := utils.GetWalletPublicKey(ctx)
	if err != nil {
		return err
	}

	mypubkeyHex := hex.EncodeToString(mypubkey.SerializeCompressed())

	reverseBoardingAddr, err := client.ReverseBoardingAddress(ctx.Context, &arkv1.ReverseBoardingAddressRequest{
		Pubkey: mypubkeyHex,
	})
	if err != nil {
		return err
	}

	explorer := utils.NewExplorer(ctx)

	boardingUtxos, err := explorer.GetUtxos(reverseBoardingAddr.GetAddress())
	if err != nil {
		return err
	}

	myselfOffchain, _, _, err := getAddress(ctx)
	if err != nil {
		return err
	}

	vtxos, err := getVtxos(ctx, nil, client, myselfOffchain, false)
	if err != nil {
		return err
	}

	var pendingBalance uint64
	var pendingVtxos []vtxo
	for _, vtxo := range vtxos {
		if vtxo.pending {
			pendingBalance += vtxo.amount
			pendingVtxos = append(pendingVtxos, vtxo)
		}
	}

	for _, utxo := range boardingUtxos {
		pendingBalance += utxo.Amount
	}

	if pendingBalance == 0 {
		return nil
	}

	receiver := receiver{
		To:     myselfOffchain,
		Amount: pendingBalance,
	}
	return selfTransferAllPendingPayments(
		ctx, client, pendingVtxos, boardingUtxos, receiver, mypubkeyHex,
	)
}

func selfTransferAllPendingPayments(
	ctx *cli.Context, client arkv1.ArkServiceClient,
	pendingVtxos []vtxo, reverseOnboardingUtxos []utils.Utxo,
	myself receiver, mypubkey string,
) error {
	inputs := make([]*arkv1.Input, 0, len(pendingVtxos)+len(reverseOnboardingUtxos))

	for _, coin := range pendingVtxos {
		inputs = append(inputs, &arkv1.Input{
			Txid: coin.txid,
			Vout: coin.vout,
		})
	}

	for _, outpoint := range reverseOnboardingUtxos {
		inputs = append(inputs, &arkv1.Input{
			Txid:                  outpoint.Txid,
			Vout:                  outpoint.Vout,
			ReverseBoardingPubkey: &mypubkey,
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
		ctx, client, registerResponse.GetId(), pendingVtxos,
		len(reverseOnboardingUtxos) > 0, secKey, receiversOutput,
	)
	if err != nil {
		return err
	}

	return utils.PrintJSON(map[string]interface{}{
		"pool_txid": poolTxID,
	})
}
