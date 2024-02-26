package main

import (
	"encoding/hex"
	"fmt"
	"time"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/ark/common/tree"
	"github.com/urfave/cli/v2"
	"github.com/vulpemventures/go-elements/payment"
	"github.com/vulpemventures/go-elements/psetv2"
)

const (
	minRelayFee = 30
)

var (
	amountOnboardFlag = cli.Uint64Flag{
		Name:     "amount",
		Usage:    "amount to onboard in sats",
		Required: true,
	}
)

var onboardCommand = cli.Command{
	Name:   "onboard",
	Usage:  "Onboard the Ark by lifting your funds",
	Action: onboardAction,
	Flags:  []cli.Flag{&amountOnboardFlag},
}

func onboardAction(ctx *cli.Context) error {
	amount := ctx.Uint64("amount")

	if amount <= 0 {
		return fmt.Errorf("missing amount flag (--amount)")
	}

	_, net := getNetwork()

	aspPubkey, err := getAspPublicKey()
	if err != nil {
		return err
	}

	roundLifetime, err := getRoundLifetime()
	if err != nil {
		return err
	}

	unilateralExitDelay, err := getUnilateralExitDelay()
	if err != nil {
		return err
	}

	userPubKey, err := getWalletPublicKey()
	if err != nil {
		return err
	}

	congestionTreeLeaf := tree.Receiver{
		Pubkey: hex.EncodeToString(userPubKey.SerializeCompressed()),
		Amount: amount,
	}

	treeFactoryFn, sharedOutputScript, sharedOutputAmount, err := tree.CraftCongestionTree(
		net.AssetID, aspPubkey, []tree.Receiver{congestionTreeLeaf},
		minRelayFee, roundLifetime, unilateralExitDelay,
	)
	if err != nil {
		return err
	}

	pay, err := payment.FromScript(sharedOutputScript, net, nil)
	if err != nil {
		return err
	}

	address, err := pay.TaprootAddress()
	if err != nil {
		return err
	}

	onchainReceiver := receiver{
		To:     address,
		Amount: sharedOutputAmount,
	}

	pset, err := sendOnchain(ctx, []receiver{onchainReceiver})
	if err != nil {
		return err
	}

	explorer := NewExplorer()
	txid, err := explorer.Broadcast(pset)
	if err != nil {
		return err
	}

	fmt.Println("onboard_txid:", txid)
	fmt.Println("waiting for confirmation... (this may take up to a minute, do not cancel the process)")

	// wait for the transaction to be confirmed
	if err := waitForTxConfirmation(ctx, txid); err != nil {
		return err
	}

	fmt.Println("transaction confirmed")

	congestionTree, err := treeFactoryFn(psetv2.InputArgs{
		Txid:    txid,
		TxIndex: 0,
	})

	if err != nil {
		return err
	}

	client, cancel, err := getClientFromState()
	if err != nil {
		return err
	}
	defer cancel()

	_, err = client.Onboard(ctx.Context, &arkv1.OnboardRequest{
		BoardingTx:     pset,
		CongestionTree: castCongestionTree(congestionTree),
		UserPubkey:     hex.EncodeToString(userPubKey.SerializeCompressed()),
	})
	if err != nil {
		return err
	}

	return nil
}

func waitForTxConfirmation(ctx *cli.Context, txid string) error {
	isConfirmed := false

	for !isConfirmed {
		time.Sleep(5 * time.Second)

		isConfirmed, _, _ = getTxBlocktime(txid)
	}

	return nil
}
