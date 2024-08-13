package covenant

import (
	"encoding/hex"
	"fmt"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/ark/client/utils"
	"github.com/ark-network/ark/common/tree"
	"github.com/urfave/cli/v2"
	"github.com/vulpemventures/go-elements/payment"
	"github.com/vulpemventures/go-elements/psetv2"
)

const minRelayFee = 30

func (c *covenantLiquidCLI) Onboard(ctx *cli.Context) error {
	amount := ctx.Uint64("amount")

	if amount <= 0 {
		return fmt.Errorf("missing amount flag (--amount)")
	}

	net, err := utils.GetNetwork(ctx)
	if err != nil {
		return err
	}

	userPubKey, err := utils.GetWalletPublicKey(ctx)
	if err != nil {
		return err
	}

	client, cancel, err := getClientFromState(ctx)
	if err != nil {
		return err
	}
	defer cancel()

	aspPubkey, err := utils.GetAspPublicKey(ctx)
	if err != nil {
		return err
	}

	roundLifetime, err := utils.GetRoundLifetime(ctx)
	if err != nil {
		return err
	}

	unilateralExitDelay, err := utils.GetUnilateralExitDelay(ctx)
	if err != nil {
		return err
	}

	congestionTreeLeaf := tree.Receiver{
		Pubkey: hex.EncodeToString(userPubKey.SerializeCompressed()),
		Amount: amount,
	}

	liquidNet := toElementsNetwork(net)

	treeFactoryFn, sharedOutputScript, sharedOutputAmount, err := tree.CraftCongestionTree(
		liquidNet.AssetID, aspPubkey, []tree.Receiver{congestionTreeLeaf},
		minRelayFee, roundLifetime, unilateralExitDelay,
	)
	if err != nil {
		return err
	}

	pay, err := payment.FromScript(sharedOutputScript, &liquidNet, nil)
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

	ptx, _ := psetv2.NewPsetFromBase64(pset)
	utx, _ := ptx.UnsignedTx()
	txid := utx.TxHash().String()

	congestionTree, err := treeFactoryFn(psetv2.InputArgs{
		Txid:    txid,
		TxIndex: 0,
	})

	if err != nil {
		return err
	}

	_, err = client.Onboard(ctx.Context, &arkv1.OnboardRequest{
		BoardingTx:     pset,
		CongestionTree: castCongestionTree(congestionTree),
		UserPubkey:     hex.EncodeToString(userPubKey.SerializeCompressed()),
	})
	if err != nil {
		return err
	}

	fmt.Println("onboard_txid:", txid)

	return nil
}
