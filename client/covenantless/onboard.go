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
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/urfave/cli/v2"
)

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

	minRelayFee, err := utils.GetMinRelayFee(ctx)
	if err != nil {
		return err
	}

	congestionTreeLeaf := bitcointree.Receiver{
		Pubkey: hex.EncodeToString(userPubKey.SerializeCompressed()),
		Amount: uint64(amount), // Convert amount to uint64
	}

	leaves := []bitcointree.Receiver{congestionTreeLeaf}

	ephemeralKey, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return err
	}

	cosigners := []*secp256k1.PublicKey{ephemeralKey.PubKey()} // TODO asp as cosigner

	sharedOutputScript, sharedOutputAmount, err := bitcointree.CraftSharedOutput(
		cosigners,
		aspPubkey,
		leaves,
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
		cosigners,
		aspPubkey,
		leaves,
		uint64(minRelayFee),
		roundLifetime,
		unilateralExitDelay,
	)
	if err != nil {
		return err
	}

	sweepClosure := bitcointree.CSVSigClosure{
		Pubkey:  aspPubkey,
		Seconds: uint(roundLifetime),
	}

	sweepTapLeaf, err := sweepClosure.Leaf()
	if err != nil {
		return err
	}

	sweepTapTree := txscript.AssembleTaprootScriptTree(*sweepTapLeaf)
	root := sweepTapTree.RootNode.TapHash()

	signer := bitcointree.NewTreeSignerSession(
		ephemeralKey,
		congestionTree,
		minRelayFee,
		root.CloneBytes(),
	)

	nonces, err := signer.GetNonces() // TODO send nonces to ASP
	if err != nil {
		return err
	}

	coordinator, err := bitcointree.NewTreeCoordinatorSession(
		congestionTree,
		minRelayFee,
		root.CloneBytes(),
		cosigners,
	)
	if err != nil {
		return err
	}

	if err := coordinator.AddNonce(ephemeralKey.PubKey(), nonces); err != nil {
		return err
	}

	aggregatedNonces, err := coordinator.AggregateNonces()
	if err != nil {
		return err
	}

	if err := signer.SetKeys(cosigners, aggregatedNonces); err != nil {
		return err
	}

	sigs, err := signer.Sign()
	if err != nil {
		return err
	}

	if err := coordinator.AddSig(ephemeralKey.PubKey(), sigs); err != nil {
		return err
	}

	signedTree, err := coordinator.SignTree()
	if err != nil {
		return err
	}

	_, err = client.Onboard(ctx.Context, &arkv1.OnboardRequest{
		BoardingTx:     partialTx,
		CongestionTree: castCongestionTree(signedTree),
		UserPubkey:     hex.EncodeToString(userPubKey.SerializeCompressed()),
	})
	if err != nil {
		return err
	}

	fmt.Println("onboard_txid:", txid)

	return nil
}
