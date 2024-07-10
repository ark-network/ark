package covenantless

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/ark-network/ark-cli/utils"
	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/ark/common/bitcointree"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/urfave/cli/v2"
)

const minRelayFee = 30

func (c *clArkBitcoinCLI) Onboard(ctx *cli.Context) error {
	isTrusted := ctx.Bool("trusted")

	amount := ctx.Uint64("amount")

	if !isTrusted && amount <= 0 {
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

	if isTrusted {
		resp, err := client.TrustedOnboarding(ctx.Context, &arkv1.TrustedOnboardingRequest{
			UserPubkey: hex.EncodeToString(userPubKey.SerializeCompressed()),
		})
		if err != nil {
			return err
		}

		return utils.PrintJSON(map[string]interface{}{
			"onboard_address": resp.Address,
		})
	}

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

	congestionTreeLeaf := bitcointree.Receiver{
		Pubkey: hex.EncodeToString(userPubKey.SerializeCompressed()),
		Amount: uint64(amount), // Convert amount to uint64
	}

	sharedOutputScript, sharedOutputAmount, err := bitcointree.CraftSharedOutput(
		[]*secp256k1.PublicKey{userPubKey}, // TODO asp as cosigner
		aspPubkey,
		[]bitcointree.Receiver{congestionTreeLeaf},
		uint64(minRelayFee),
		roundLifetime,
		unilateralExitDelay,
	)
	if err != nil {
		return err
	}

	netParams := toChainParams(net)

	address, err := btcutil.NewAddressTaproot(sharedOutputScript[2:], &netParams)
	if err != nil {
		return err
	}

	onchainReceiver := receiver{
		To:     address.EncodeAddress(),
		Amount: uint64(sharedOutputAmount),
	}

	partialTx, err := sendOnchain(ctx, []receiver{onchainReceiver})
	if err != nil {
		return err
	}

	ptx, err := psbt.NewFromRawBytes(strings.NewReader(partialTx), true)
	if err != nil {
		return err
	}
	txid := ptx.UnsignedTx.TxHash().String()

	congestionTree, err := bitcointree.CraftCongestionTree(
		&wire.OutPoint{
			Hash:  ptx.UnsignedTx.TxHash(),
			Index: 0,
		},
		[]*secp256k1.PublicKey{userPubKey},
		aspPubkey,
		[]bitcointree.Receiver{congestionTreeLeaf},
		uint64(minRelayFee),
		roundLifetime,
		unilateralExitDelay,
	)
	if err != nil {
		return err
	}

	_, err = client.Onboard(ctx.Context, &arkv1.OnboardRequest{
		BoardingTx:     partialTx,
		CongestionTree: castCongestionTree(congestionTree),
		UserPubkey:     hex.EncodeToString(userPubKey.SerializeCompressed()),
	})
	if err != nil {
		return err
	}

	fmt.Println("onboard_txid:", txid)

	return nil
}
