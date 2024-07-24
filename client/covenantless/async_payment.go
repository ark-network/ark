package covenantless

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/ark-network/ark-cli/utils"
	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/urfave/cli/v2"
)

func (c *clArkBitcoinCLI) SendAsync(ctx *cli.Context) error {
	receiver := ctx.String("to")

	if receiver == "" {
		return fmt.Errorf("receiver address is required")
	}

	isOnchain, _, pubkey, err := decodeReceiverAddress(receiver)
	if err != nil {
		return err
	}

	if isOnchain {
		return fmt.Errorf("receiver address is onchain")
	}

	explorer := utils.NewExplorer(ctx)
	client, close, err := getClientFromState(ctx)
	if err != nil {
		return err
	}
	defer close()

	offchainAddr, _, _, err := getAddress(ctx)
	if err != nil {
		return err
	}

	vtxos, err := getVtxos(ctx, explorer, client, offchainAddr, false)
	if err != nil {
		return err
	}

	// print vtxos to user
	fmt.Println("Select the vtxo to send async: ")
	for i, vtxo := range vtxos {
		fmt.Printf("%d: %s (%d sats)\n", i, vtxo.txid, vtxo.amount)
	}

	// get user input
	var idx int
	fmt.Print("Enter the index of the vtxo to send: ")
	_, err = fmt.Scanf("%d", &idx)
	if err != nil {
		return err
	}

	if idx < 0 || idx >= len(vtxos) {
		return fmt.Errorf("invalid index")
	}

	vtxo := vtxos[idx]

	resp, err := client.CreateAsyncPayment(
		ctx.Context, &arkv1.CreateAsyncPaymentRequest{
			Input: &arkv1.Input{
				Txid: vtxo.txid,
				Vout: vtxo.vout,
			},
			ReceiverPubkey: hex.EncodeToString(pubkey.SerializeCompressed()),
		})
	if err != nil {
		return err
	}

	fmt.Println("Async payment created")
	fmt.Printf("Redeem tx: %s\n", resp.SignedRedeemTx)
	fmt.Printf("Forfeit tx: %s\n", resp.UsignedUnconditionalForfeitTx)

	// TODO verify the redeem tx signature

	fmt.Println("Signing forfeit...")

	forfeitPtx, err := psbt.NewFromRawBytes(strings.NewReader(resp.UsignedUnconditionalForfeitTx), true)
	if err != nil {
		return err
	}

	redeemPtx, err := psbt.NewFromRawBytes(strings.NewReader(resp.SignedRedeemTx), true)
	if err != nil {
		return err
	}

	seckey, err := utils.PrivateKeyFromPassword(ctx)
	if err != nil {
		return err
	}

	if err := signPsbt(ctx, forfeitPtx, explorer, seckey); err != nil {
		return err
	}

	if err := signPsbt(ctx, redeemPtx, explorer, seckey); err != nil {
		return err
	}

	signedForfeit, err := forfeitPtx.B64Encode()
	if err != nil {
		return err
	}

	signedRedeem, err := redeemPtx.B64Encode()
	if err != nil {
		return err
	}

	fmt.Printf("Signed forfeit tx: %s\n", signedForfeit)

	if _, err = client.CompleteAsyncPayment(ctx.Context, &arkv1.CompleteAsyncPaymentRequest{
		SignedRedeemTx:               signedRedeem,
		SignedUnconditionalForfeitTx: signedForfeit,
	}); err != nil {
		return err
	}

	return nil
}
