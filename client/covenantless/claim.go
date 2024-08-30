package covenantless

import (
	"encoding/hex"
	"fmt"
	"time"

	"github.com/ark-network/ark/common"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/ark/client/utils"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/urfave/cli/v2"
)

func (c *clArkBitcoinCLI) Claim(ctx *cli.Context) error {
	client, cancel, err := getClientFromState(ctx)
	if err != nil {
		return err
	}
	defer cancel()

	offchainAddr, onboardingAddr, _, err := getAddress(ctx)
	if err != nil {
		return err
	}

	onboardingExitDelay, err := utils.GetOnboardingExitDelay(ctx)
	if err != nil {
		return err
	}

	explorer := utils.NewExplorer(ctx)

	boardingUtxosFromExplorer, err := explorer.GetUtxos(onboardingAddr.EncodeAddress())
	if err != nil {
		return err
	}

	now := time.Now()
	boardingUtxos := make([]utils.Utxo, 0, len(boardingUtxosFromExplorer))
	for _, utxo := range boardingUtxosFromExplorer {
		u := utils.NewUtxo(utxo, uint(onboardingExitDelay))
		if u.SpendableAt.Before(now) {
			continue // cannot claim if onchain spendable
		}

		boardingUtxos = append(boardingUtxos, u)
	}

	vtxos, err := getVtxos(ctx, nil, client, offchainAddr, false)
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
		To:     offchainAddr,
		Amount: pendingBalance,
	}

	if len(ctx.String("password")) == 0 {
		if ok := askForConfirmation(
			fmt.Sprintf(
				"claim %d satoshis from %d pending payments and %d onboarding utxos",
				pendingBalance, len(pendingVtxos), len(boardingUtxos),
			),
		); !ok {
			return nil
		}
	}

	return selfTransferAllPendingPayments(
		ctx, client, pendingVtxos, boardingUtxos, receiver,
	)
}

func selfTransferAllPendingPayments(
	ctx *cli.Context,
	client arkv1.ArkServiceClient,
	pendingVtxos []vtxo,
	onboardingUtxos []utils.Utxo,
	myself receiver,
) error {
	inputs := make([]*arkv1.Input, 0, len(pendingVtxos)+len(onboardingUtxos))

	for _, coin := range pendingVtxos {
		inputs = append(inputs, &arkv1.Input{
			Txid: coin.txid,
			Vout: coin.vout,
		})
	}

	if len(onboardingUtxos) > 0 {
		// if there are onboarding utxos, we need to include the pubkey
		_, pubkey, _, err := common.DecodeAddress(myself.To)
		if err != nil {
			return err
		}

		mypubkey := hex.EncodeToString(pubkey.SerializeCompressed())

		for _, outpoint := range onboardingUtxos {
			inputs = append(inputs, &arkv1.Input{
				Txid:                  outpoint.Txid,
				Vout:                  outpoint.Vout,
				ReverseBoardingPubkey: &mypubkey,
			})
		}
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

	ephemeralKey, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return err
	}

	pubkey := hex.EncodeToString(ephemeralKey.PubKey().SerializeCompressed())

	registerResponse, err := client.RegisterPayment(
		ctx.Context,
		&arkv1.RegisterPaymentRequest{
			Inputs:          inputs,
			EphemeralPubkey: &pubkey,
		},
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
		len(onboardingUtxos) > 0, secKey, receiversOutput, ephemeralKey,
	)
	if err != nil {
		return err
	}

	return utils.PrintJSON(map[string]interface{}{
		"pool_txid": poolTxID,
	})
}
