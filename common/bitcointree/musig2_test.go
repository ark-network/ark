package bitcointree_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/ark-network/ark/common/bitcointree"
	"github.com/ark-network/ark/common/tree"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"
)

const (
	dustAmount  = 100
	minRelayFee = 1000
	exitDelay   = 512
	lifetime    = 1024
)

var testTxid, _ = chainhash.NewHashFromStr("49f8664acc899be91902f8ade781b7eeb9cbe22bdd9efbc36e56195de21bcd12")

func TestRoundTripSignTree(t *testing.T) {
	fixtures := parseFixtures(t)
	for _, f := range fixtures.Valid {
		alice, err := secp256k1.GeneratePrivateKey()
		require.NoError(t, err)

		bob, err := secp256k1.GeneratePrivateKey()
		require.NoError(t, err)

		asp, err := secp256k1.GeneratePrivateKey()
		require.NoError(t, err)

		cosigners := make([]*secp256k1.PublicKey, 0)
		cosigners = append(cosigners, alice.PubKey())
		cosigners = append(cosigners, bob.PubKey())
		cosigners = append(cosigners, asp.PubKey())

		_, sharedOutputAmount, err := bitcointree.CraftSharedOutput(
			cosigners,
			asp.PubKey(),
			castReceivers(f.Receivers),
			minRelayFee,
			dustAmount,
			lifetime,
		)
		require.NoError(t, err)

		// Create a new tree
		tree, err := bitcointree.CraftCongestionTree(
			&wire.OutPoint{
				Hash:  *testTxid,
				Index: 0,
			},
			cosigners,
			asp.PubKey(),
			castReceivers(f.Receivers),
			minRelayFee,
			dustAmount,
			lifetime,
		)
		require.NoError(t, err)

		sweepClosure := bitcointree.CSVSigClosure{
			Pubkey:  asp.PubKey(),
			Seconds: lifetime,
		}

		sweepTapLeaf, err := sweepClosure.Leaf()
		require.NoError(t, err)

		sweepTapTree := txscript.AssembleTaprootScriptTree(*sweepTapLeaf)
		root := sweepTapTree.RootNode.TapHash()

		aspCoordinator, err := bitcointree.NewTreeCoordinatorSession(
			sharedOutputAmount,
			tree,
			root.CloneBytes(),
			[]*secp256k1.PublicKey{alice.PubKey(), bob.PubKey(), asp.PubKey()},
		)
		require.NoError(t, err)

		aliceSession := bitcointree.NewTreeSignerSession(alice, sharedOutputAmount, tree, root.CloneBytes())
		bobSession := bitcointree.NewTreeSignerSession(bob, sharedOutputAmount, tree, root.CloneBytes())
		aspSession := bitcointree.NewTreeSignerSession(asp, sharedOutputAmount, tree, root.CloneBytes())

		aliceNonces, err := aliceSession.GetNonces()
		require.NoError(t, err)

		bobNonces, err := bobSession.GetNonces()
		require.NoError(t, err)

		aspNonces, err := aspSession.GetNonces()
		require.NoError(t, err)

		s := bytes.NewBuffer(nil)

		err = aspNonces[0][0].Encode(s)
		require.NoError(t, err)

		bitcointreeNonce := new(bitcointree.Musig2Nonce)
		err = bitcointreeNonce.Decode(s)
		require.NoError(t, err)

		require.Equal(t, aspNonces[0][0], bitcointreeNonce)

		var serializedNonces bytes.Buffer

		err = aspNonces.Encode(&serializedNonces)
		require.NoError(t, err)

		decodedNonces, err := bitcointree.DecodeNonces(&serializedNonces)
		require.NoError(t, err)

		for i, nonces := range aspNonces {
			for j, nonce := range nonces {
				require.Equal(t, nonce.PubNonce, decodedNonces[i][j].PubNonce, fmt.Sprintf("matrix nonce not equal at index i: %d, j: %d", i, j))
			}
		}

		err = aspCoordinator.AddNonce(alice.PubKey(), aliceNonces)
		require.NoError(t, err)

		err = aspCoordinator.AddNonce(bob.PubKey(), bobNonces)
		require.NoError(t, err)

		err = aspCoordinator.AddNonce(asp.PubKey(), aspNonces)
		require.NoError(t, err)

		aggregatedNonce, err := aspCoordinator.AggregateNonces()
		require.NoError(t, err)

		// coordinator sends the combined nonce to all signers

		err = aliceSession.SetKeys(
			cosigners,
		)
		require.NoError(t, err)

		err = aliceSession.SetAggregatedNonces(
			aggregatedNonce,
		)
		require.NoError(t, err)

		err = bobSession.SetKeys(
			cosigners,
		)
		require.NoError(t, err)

		err = bobSession.SetAggregatedNonces(
			aggregatedNonce,
		)
		require.NoError(t, err)

		err = aspSession.SetKeys(
			cosigners,
		)
		require.NoError(t, err)

		err = aspSession.SetAggregatedNonces(
			aggregatedNonce,
		)
		require.NoError(t, err)

		aliceSig, err := aliceSession.Sign()
		require.NoError(t, err)

		bobSig, err := bobSession.Sign()
		require.NoError(t, err)

		aspSig, err := aspSession.Sign()
		require.NoError(t, err)

		// check that the sigs are serializable

		serializedSigs := bytes.NewBuffer(nil)

		err = aspSig.Encode(serializedSigs)
		require.NoError(t, err)

		decodedSigs, err := bitcointree.DecodeSignatures(serializedSigs)
		require.NoError(t, err)

		for i, sigs := range aspSig {
			for j, sig := range sigs {
				require.Equal(t, sig.S, decodedSigs[i][j].S, fmt.Sprintf("matrix sig not equal at index i: %d, j: %d", i, j))
			}
		}

		// coordinator receives the signatures and combines them
		err = aspCoordinator.AddSig(alice.PubKey(), aliceSig)
		require.NoError(t, err)

		err = aspCoordinator.AddSig(bob.PubKey(), bobSig)
		require.NoError(t, err)

		err = aspCoordinator.AddSig(asp.PubKey(), aspSig)
		require.NoError(t, err)

		signedTree, err := aspCoordinator.SignTree()
		require.NoError(t, err)

		// verify the tree
		aggregatedKey, err := bitcointree.AggregateKeys(cosigners, root.CloneBytes())
		require.NoError(t, err)

		err = bitcointree.ValidateTreeSigs(
			root.CloneBytes(),
			aggregatedKey.FinalKey,
			sharedOutputAmount,
			signedTree,
		)
		require.NoError(t, err)
	}
}

type receiverFixture struct {
	Amount int64  `json:"amount"`
	Pubkey string `json:"pubkey"`
}

func castReceivers(receivers []receiverFixture) []tree.VtxoLeaf {
	receiversOut := make([]tree.VtxoLeaf, 0, len(receivers))
	for _, r := range receivers {
		receiversOut = append(receiversOut, tree.VtxoLeaf{
			Pubkey: r.Pubkey,
			Amount: uint64(r.Amount),
		})
	}
	return receiversOut
}

type fixture struct {
	Valid []struct {
		Receivers []receiverFixture `json:"receivers"`
	} `json:"valid"`
}

func parseFixtures(t *testing.T) fixture {
	file, err := os.ReadFile("testdata/musig2.json")
	require.NoError(t, err)
	v := map[string]interface{}{}
	err = json.Unmarshal(file, &v)
	require.NoError(t, err)

	vv := v["treeSignature"].(map[string]interface{})
	file, _ = json.Marshal(vv)
	var fixtures fixture
	err = json.Unmarshal(file, &fixtures)
	require.NoError(t, err)

	return fixtures
}
