package bitcointree_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/ark-network/ark/common/bitcointree"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"
)

const (
	minRelayFee = 1000
	exitDelay   = 512
	lifetime    = 1024
)

var testTxid, _ = chainhash.NewHashFromStr("49f8664acc899be91902f8ade781b7eeb9cbe22bdd9efbc36e56195de21bcd12")

func TestRoundTripSignTree(t *testing.T) {
	fixtures := parseFixtures(t)
	for _, f := range fixtures.Valid {
		// Generate 20 cosigners
		cosigners := make([]*secp256k1.PrivateKey, 20)
		cosignerPubKeys := make([]*btcec.PublicKey, 20)
		for i := 0; i < 20; i++ {
			privKey, err := secp256k1.GeneratePrivateKey()
			require.NoError(t, err)
			cosigners[i] = privKey
			cosignerPubKeys[i] = privKey.PubKey()
		}

		asp, err := secp256k1.GeneratePrivateKey()
		require.NoError(t, err)

		_, sharedOutputAmount, err := bitcointree.CraftSharedOutput(
			cosignerPubKeys,
			asp.PubKey(),
			castReceivers(f.Receivers, asp.PubKey()),
			minRelayFee,
			lifetime,
		)
		require.NoError(t, err)

		// Create a new tree
		tree, err := bitcointree.CraftCongestionTree(
			&wire.OutPoint{
				Hash:  *testTxid,
				Index: 0,
			},
			cosignerPubKeys,
			asp.PubKey(),
			castReceivers(f.Receivers, asp.PubKey()),
			minRelayFee,
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
			cosignerPubKeys,
		)
		require.NoError(t, err)

		// Create signer sessions for all cosigners
		signerSessions := make([]bitcointree.SignerSession, 20)
		for i, cosigner := range cosigners {
			signerSessions[i] = bitcointree.NewTreeSignerSession(cosigner, sharedOutputAmount, tree, root.CloneBytes())
		}

		// Get nonces from all signers
		for i, session := range signerSessions {
			nonces, err := session.GetNonces()
			require.NoError(t, err)
			err = aspCoordinator.AddNonce(cosignerPubKeys[i], nonces)
			require.NoError(t, err)
		}

		aggregatedNonce, err := aspCoordinator.AggregateNonces()
		require.NoError(t, err)

		// Set keys and aggregated nonces for all signers
		for _, session := range signerSessions {
			err = session.SetKeys(cosignerPubKeys)
			require.NoError(t, err)
			err = session.SetAggregatedNonces(aggregatedNonce)
			require.NoError(t, err)
		}

		// Get signatures from all signers
		for i, session := range signerSessions {
			sig, err := session.Sign()
			require.NoError(t, err)
			err = aspCoordinator.AddSig(cosignerPubKeys[i], sig)
			require.NoError(t, err)
		}

		signedTree, err := aspCoordinator.SignTree()
		require.NoError(t, err)

		// verify the tree
		aggregatedKey, err := bitcointree.AggregateKeys(cosignerPubKeys, root.CloneBytes())
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

func (r receiverFixture) toVtxoScript(asp *secp256k1.PublicKey) bitcointree.VtxoScript {
	bytesKey, err := hex.DecodeString(r.Pubkey)
	if err != nil {
		panic(err)
	}

	pubkey, err := secp256k1.ParsePubKey(bytesKey)
	if err != nil {
		panic(err)
	}

	return &bitcointree.DefaultVtxoScript{
		Owner:     pubkey,
		Asp:       asp,
		ExitDelay: exitDelay,
	}
}

func castReceivers(receivers []receiverFixture, asp *secp256k1.PublicKey) []bitcointree.Receiver {
	receiversOut := make([]bitcointree.Receiver, 0, len(receivers))
	for _, r := range receivers {
		receiversOut = append(receiversOut, bitcointree.Receiver{
			Script: r.toVtxoScript(asp),
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
