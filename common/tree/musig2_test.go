package tree_test

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/tree"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

var (
	vtxoTreeExpiry   = common.RelativeLocktime{Type: common.LocktimeTypeBlock, Value: 144}
	rootInput, _     = wire.NewOutPointFromString("49f8664acc899be91902f8ade781b7eeb9cbe22bdd9efbc36e56195de21bcd12:0")
	serverPrivKey, _ = btcec.NewPrivateKey()
	sweepScript, _   = (&tree.CSVMultisigClosure{
		MultisigClosure: tree.MultisigClosure{PubKeys: []*btcec.PublicKey{serverPrivKey.PubKey()}},
		Locktime:        vtxoTreeExpiry,
	}).Script()
	sweepRoot      = txscript.NewBaseTapLeaf(sweepScript).TapHash()
	receiverCounts = []int{1, 2, 20, 128}
)

func TestBuildAndSignVtxoTree(t *testing.T) {
	t.Parallel()

	testVectors, err := makeTestVectors()
	require.NoError(t, err)
	require.NotEmpty(t, testVectors)

	for _, v := range testVectors {
		t.Run(v.name, func(t *testing.T) {
			sharedOutScript, sharedOutAmount, err := tree.CraftSharedOutput(
				v.receivers, sweepRoot[:],
			)
			require.NoError(t, err)
			require.NotNil(t, sharedOutScript)
			require.NotZero(t, sharedOutAmount)

			vtxoTree, err := tree.BuildVtxoTree(
				rootInput, v.receivers, sweepRoot[:], vtxoTreeExpiry,
			)
			require.NoError(t, err)
			require.NotNil(t, vtxoTree)

			coordinator, err := tree.NewTreeCoordinatorSession(
				sharedOutAmount, vtxoTree, sweepRoot[:],
			)
			require.NoError(t, err)
			require.NotNil(t, coordinator)

			signers, err := makeCosigners(v.privKeys, sharedOutAmount, vtxoTree)
			require.NoError(t, err)
			require.NotNil(t, signers)

			err = makeAggregatedNonces(signers, coordinator, checkNoncesRoundtrip(t))
			require.NoError(t, err)

			signedTree, err := makeAggregatedSignatures(signers, coordinator, checkSigsRoundtrip(t))
			require.NoError(t, err)
			require.NotNil(t, signedTree)

			// validate signatures
			err = tree.ValidateTreeSigs(sweepRoot[:], sharedOutAmount, signedTree)
			require.NoError(t, err)
		})
	}
}

func checkNoncesRoundtrip(t *testing.T) func(nonces tree.TreeNonces) {
	return func(nonces tree.TreeNonces) {
		// Marshal to JSON
		jsonData, err := json.Marshal(nonces)
		require.NoError(t, err)

		// Unmarshal from JSON
		decodedNonces := make(tree.TreeNonces)
		err = json.Unmarshal(jsonData, &decodedNonces)
		require.NoError(t, err)

		// Compare the nonces
		for txid, nonce := range nonces {
			decodedNonce, exists := decodedNonces[txid]
			require.True(t, exists)
			require.Equal(t, nonce.PubNonce, decodedNonce.PubNonce)
		}
	}
}

func checkSigsRoundtrip(t *testing.T) func(sigs tree.TreePartialSigs) {
	return func(sigs tree.TreePartialSigs) {
		// Marshal to JSON
		jsonData, err := json.Marshal(sigs)
		require.NoError(t, err)

		t.Logf("sigs: %s", string(jsonData))
		t.Fail()

		// Unmarshal from JSON
		decodedSigs := make(tree.TreePartialSigs)
		err = json.Unmarshal(jsonData, &decodedSigs)
		require.NoError(t, err)

		// Compare the signatures
		for txid, sig := range sigs {
			decodedSig, exists := decodedSigs[txid]
			require.True(t, exists)
			if sig == nil {
				require.Nil(t, decodedSig)
			} else {
				require.Equal(t, sig.S, decodedSig.S)
			}
		}
	}
}

func makeCosigners(
	keys []*btcec.PrivateKey, sharedOutAmount int64, vtxoTree *tree.TxGraph,
) (map[string]tree.SignerSession, error) {
	signers := make(map[string]tree.SignerSession)
	for _, prvkey := range keys {
		session := tree.NewTreeSignerSession(prvkey)
		if err := session.Init(sweepRoot[:], sharedOutAmount, vtxoTree); err != nil {
			return nil, err
		}
		signers[keyToStr(prvkey)] = session
	}

	// create signer session for the server itself
	serverSession := tree.NewTreeSignerSession(serverPrivKey)
	if err := serverSession.Init(sweepRoot[:], sharedOutAmount, vtxoTree); err != nil {
		return nil, err
	}
	signers[keyToStr(serverPrivKey)] = serverSession
	return signers, nil
}

func makeAggregatedNonces(
	signers map[string]tree.SignerSession, coordinator tree.CoordinatorSession,
	checkNoncesRoundtrip func(tree.TreeNonces),
) error {
	for pk, session := range signers {
		buf, err := hex.DecodeString(pk)
		if err != nil {
			return err
		}
		pubkey, err := btcec.ParsePubKey(buf)
		if err != nil {
			return err
		}

		nonces, err := session.GetNonces()
		if err != nil {
			return err
		}
		checkNoncesRoundtrip(nonces)

		coordinator.AddNonce(pubkey, nonces)
	}

	aggregatedNonce, err := coordinator.AggregateNonces()
	if err != nil {
		return err
	}

	// set the aggregated nonces for all signers sessions
	for _, session := range signers {
		session.SetAggregatedNonces(aggregatedNonce)
	}
	return nil
}

func makeAggregatedSignatures(
	signers map[string]tree.SignerSession, coordinator tree.CoordinatorSession,
	checkSigsRoundtrip func(tree.TreePartialSigs),
) (*tree.TxGraph, error) {
	for pk, session := range signers {
		buf, err := hex.DecodeString(pk)
		if err != nil {
			return nil, err
		}
		pubkey, err := btcec.ParsePubKey(buf)
		if err != nil {
			return nil, err
		}

		sigs, err := session.Sign()
		if err != nil {
			return nil, err
		}
		checkSigsRoundtrip(sigs)

		coordinator.AddSignatures(pubkey, sigs)
	}

	// aggregate signatures
	return coordinator.SignTree()
}

type vtxoTreeTestCase struct {
	name      string
	receivers []tree.Leaf
	privKeys  []*btcec.PrivateKey
}

func makeTestVectors() ([]vtxoTreeTestCase, error) {
	vectors := make([]vtxoTreeTestCase, 0, len(receiverCounts))
	for _, count := range receiverCounts {
		testCase, err := generateMockedReceivers(count)
		if err != nil {
			return nil, err
		}
		vectors = append(vectors, testCase)
	}
	return vectors, nil
}

func generateMockedReceivers(num int) (vtxoTreeTestCase, error) {
	receivers := make([]tree.Leaf, 0, num)
	privKeys := make([]*btcec.PrivateKey, 0, num)
	for i := 0; i < num; i++ {
		prvkey, err := btcec.NewPrivateKey()
		if err != nil {
			return vtxoTreeTestCase{}, err
		}
		receivers = append(receivers, tree.Leaf{
			Script: "0000000000000000000000000000000000000000000000000000000000000002",
			Amount: uint64((i + 1) * 1000),
			CosignersPublicKeys: []string{
				hex.EncodeToString(prvkey.PubKey().SerializeCompressed()),
				hex.EncodeToString(serverPrivKey.PubKey().SerializeCompressed()),
			},
		})
		privKeys = append(privKeys, prvkey)
	}
	return vtxoTreeTestCase{
		name:      fmt.Sprintf("%d receivers", num),
		receivers: receivers,
		privKeys:  privKeys,
	}, nil
}

func keyToStr(key *btcec.PrivateKey) string {
	return hex.EncodeToString(key.PubKey().SerializeCompressed())
}
