package bitcointree_test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/bitcointree"
	"github.com/ark-network/ark/common/tree"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

const (
	minRelayFee = 1000
	exitDelay   = 512
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
			sharedOutScript, sharedOutAmount, err := bitcointree.CraftSharedOutput(
				v.receivers, minRelayFee, sweepRoot[:],
			)
			require.NoError(t, err)
			require.NotNil(t, sharedOutScript)
			require.NotZero(t, sharedOutAmount)

			vtxoTree, err := bitcointree.BuildVtxoTree(
				rootInput, v.receivers, minRelayFee, sweepRoot[:], vtxoTreeExpiry,
			)
			require.NoError(t, err)
			require.NotNil(t, vtxoTree)

			coordinator, err := bitcointree.NewTreeCoordinatorSession(
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
			err = bitcointree.ValidateTreeSigs(sweepRoot[:], sharedOutAmount, signedTree)
			require.NoError(t, err)
		})
	}
}

func checkNoncesRoundtrip(t *testing.T) func(nonces bitcointree.TreeNonces) {
	return func(nonces bitcointree.TreeNonces) {
		var encodedNonces bytes.Buffer
		err := nonces.Encode(&encodedNonces)
		require.NoError(t, err)

		decodedNonces, err := bitcointree.DecodeNonces(&encodedNonces)
		require.NoError(t, err)
		for i, nonceRow := range nonces {
			for j, nonce := range nonceRow {
				require.Equal(t, nonce, decodedNonces[i][j])
			}
		}
	}
}

func checkSigsRoundtrip(t *testing.T) func(sigs bitcointree.TreePartialSigs) {
	return func(sigs bitcointree.TreePartialSigs) {
		var encodedSig bytes.Buffer
		err := sigs.Encode(&encodedSig)
		require.NoError(t, err)
		decodedSig, err := bitcointree.DecodeSignatures(&encodedSig)
		require.NoError(t, err)
		for i, sigRow := range sigs {
			for j, sig := range sigRow {
				if sig == nil {
					require.Nil(t, decodedSig[i][j])
				} else {
					require.Equal(t, sig.S, decodedSig[i][j].S)
				}
			}
		}
	}
}

func makeCosigners(
	keys []*btcec.PrivateKey, sharedOutAmount int64, vtxoTree tree.VtxoTree,
) (map[string]bitcointree.SignerSession, error) {
	signers := make(map[string]bitcointree.SignerSession)
	for _, prvkey := range keys {
		session := bitcointree.NewTreeSignerSession(prvkey)
		if err := session.Init(sweepRoot[:], sharedOutAmount, vtxoTree); err != nil {
			return nil, err
		}
		signers[keyToStr(prvkey)] = session
	}

	// create signer session for the server itself
	serverSession := bitcointree.NewTreeSignerSession(serverPrivKey)
	if err := serverSession.Init(sweepRoot[:], sharedOutAmount, vtxoTree); err != nil {
		return nil, err
	}
	signers[keyToStr(serverPrivKey)] = serverSession
	return signers, nil
}

func makeAggregatedNonces(
	signers map[string]bitcointree.SignerSession, coordinator bitcointree.CoordinatorSession,
	checkNoncesRoundtrip func(bitcointree.TreeNonces),
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
	signers map[string]bitcointree.SignerSession, coordinator bitcointree.CoordinatorSession,
	checkSigsRoundtrip func(bitcointree.TreePartialSigs),
) (tree.VtxoTree, error) {
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

type testCase struct {
	name      string
	receivers []tree.VtxoLeaf
	privKeys  []*btcec.PrivateKey
}

func makeTestVectors() ([]testCase, error) {
	vectors := make([]testCase, 0, len(receiverCounts))
	for _, count := range receiverCounts {
		receivers, privKeys, err := generateMockedReceivers(count)
		if err != nil {
			return nil, err
		}

		// add mixed types test case if count is between 2 and 32
		if count > 1 && count < 32 {
			vectors = append(vectors, testCase{
				name:      fmt.Sprintf("%d receivers Mixed Signing Types", len(receivers)),
				receivers: withMixedSigningTypes(receivers),
				privKeys:  privKeys,
			})
		}

		// add SignAll test case if count is less than 32
		if count < 32 {
			vectors = append(vectors, testCase{
				name:      fmt.Sprintf("%d receivers SignAll", len(receivers)),
				receivers: withSigningType(tree.SignAll, receivers),
				privKeys:  privKeys,
			})
		}

		// always add SignBranch test case
		vectors = append(vectors, testCase{
			name:      fmt.Sprintf("%d receivers SignBranch", len(receivers)),
			receivers: withSigningType(tree.SignBranch, receivers),
			privKeys:  privKeys,
		})
	}
	return vectors, nil
}

func generateMockedReceivers(num int) ([]tree.VtxoLeaf, []*btcec.PrivateKey, error) {
	receivers := make([]tree.VtxoLeaf, 0, num)
	privKeys := make([]*btcec.PrivateKey, 0, num)
	for i := 0; i < num; i++ {
		prvkey, err := btcec.NewPrivateKey()
		if err != nil {
			return nil, nil, err
		}
		receivers = append(receivers, tree.VtxoLeaf{
			PubKey: "0000000000000000000000000000000000000000000000000000000000000002",
			Amount: uint64((i + 1) * 1000),
			Musig2Data: &tree.Musig2{
				CosignersPublicKeys: []string{
					hex.EncodeToString(prvkey.PubKey().SerializeCompressed()),
					hex.EncodeToString(serverPrivKey.PubKey().SerializeCompressed()),
				},
				SigningType: tree.SignAll,
			},
		})
		privKeys = append(privKeys, prvkey)
	}
	return receivers, privKeys, nil
}

func withSigningType(signingType tree.SigningType, receivers []tree.VtxoLeaf) []tree.VtxoLeaf {
	newReceivers := make([]tree.VtxoLeaf, 0, len(receivers))
	for _, receiver := range receivers {
		newReceivers = append(newReceivers, tree.VtxoLeaf{
			PubKey: receiver.PubKey,
			Amount: receiver.Amount,
			Musig2Data: &tree.Musig2{
				CosignersPublicKeys: receiver.Musig2Data.CosignersPublicKeys,
				SigningType:         signingType,
			},
		})
	}
	return newReceivers
}

func withMixedSigningTypes(receivers []tree.VtxoLeaf) []tree.VtxoLeaf {
	first := withSigningType(tree.SignAll, receivers[:len(receivers)/2])
	second := withSigningType(tree.SignBranch, receivers[len(receivers)/2:])
	return append(first, second...)
}

func keyToStr(key *btcec.PrivateKey) string {
	return hex.EncodeToString(key.PubKey().SerializeCompressed())
}
