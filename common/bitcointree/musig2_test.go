package bitcointree_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/bitcointree"
	"github.com/ark-network/ark/common/tree"
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
)

var vtxoTreeExpiry = common.RelativeLocktime{Type: common.LocktimeTypeBlock, Value: 144}

var testTxid, _ = chainhash.NewHashFromStr("49f8664acc899be91902f8ade781b7eeb9cbe22bdd9efbc36e56195de21bcd12")

func TestRoundTripSignTree(t *testing.T) {
	fixtures := parseFixtures(t)
	for _, f := range fixtures.Valid {
		// Generate 20 cosigners
		cosigners := make([]*secp256k1.PrivateKey, 20)
		cosignerPubkeys := make([]*btcec.PublicKey, 20)
		for i := 0; i < 20; i++ {
			prvkey, err := secp256k1.GeneratePrivateKey()
			require.NoError(t, err)
			cosigners[i] = prvkey
			cosignerPubkeys[i] = prvkey.PubKey()
		}

		server, err := secp256k1.GeneratePrivateKey()
		require.NoError(t, err)

		_, sharedOutputAmount, err := bitcointree.CraftSharedOutput(
			cosignerPubkeys,
			server.PubKey(),
			castReceivers(f.Receivers),
			minRelayFee,
			vtxoTreeExpiry,
		)
		require.NoError(t, err)

		vtxoTree, err := bitcointree.BuildVtxoTree(
			&wire.OutPoint{
				Hash:  *testTxid,
				Index: 0,
			},
			cosignerPubkeys,
			server.PubKey(),
			castReceivers(f.Receivers),
			minRelayFee,
			vtxoTreeExpiry,
		)
		require.NoError(t, err)

		sweepClosure := &tree.CSVMultisigClosure{
			MultisigClosure: tree.MultisigClosure{PubKeys: []*secp256k1.PublicKey{server.PubKey()}},
			Locktime:        vtxoTreeExpiry,
		}

		sweepScript, err := sweepClosure.Script()
		require.NoError(t, err)

		sweepTapLeaf := txscript.NewBaseTapLeaf(sweepScript)
		sweepTapTree := txscript.AssembleTaprootScriptTree(sweepTapLeaf)
		root := sweepTapTree.RootNode.TapHash()

		serverCoordinator, err := bitcointree.NewTreeCoordinatorSession(
			sharedOutputAmount,
			vtxoTree,
			root.CloneBytes(),
			cosignerPubkeys,
		)
		require.NoError(t, err)

		// Create signer sessions for all cosigners
		signerSessions := make([]bitcointree.SignerSession, 20)
		for i, cosigner := range cosigners {
			signerSessions[i] = bitcointree.NewTreeSignerSession(cosigner, sharedOutputAmount, vtxoTree, root.CloneBytes())
		}

		// Get nonces from all signers
		for i, session := range signerSessions {
			nonces, err := session.GetNonces()
			require.NoError(t, err)
			err = serverCoordinator.AddNonce(cosignerPubkeys[i], nonces)
			require.NoError(t, err)
		}

		aggregatedNonce, err := serverCoordinator.AggregateNonces()
		require.NoError(t, err)

		// Set keys and aggregated nonces for all signers
		for _, session := range signerSessions {
			err = session.SetKeys(cosignerPubkeys)
			require.NoError(t, err)
			err = session.SetAggregatedNonces(aggregatedNonce)
			require.NoError(t, err)
		}

		// Get signatures from all signers
		for i, session := range signerSessions {
			sig, err := session.Sign()
			require.NoError(t, err)
			err = serverCoordinator.AddSig(cosignerPubkeys[i], sig)
			require.NoError(t, err)
		}

		signedTree, err := serverCoordinator.SignTree()
		require.NoError(t, err)

		// verify the tree
		aggregatedKey, err := bitcointree.AggregateKeys(cosignerPubkeys, root.CloneBytes())
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
			PubKey: r.Pubkey,
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
