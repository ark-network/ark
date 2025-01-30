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

var (
	vtxoTreeExpiry   = common.RelativeLocktime{Type: common.LocktimeTypeBlock, Value: 144}
	testTxid, _      = chainhash.NewHashFromStr("49f8664acc899be91902f8ade781b7eeb9cbe22bdd9efbc36e56195de21bcd12")
	serverPrivKey, _ = secp256k1.GeneratePrivateKey()
	sweepScript, _   = (&tree.CSVMultisigClosure{
		MultisigClosure: tree.MultisigClosure{PubKeys: []*secp256k1.PublicKey{serverPrivKey.PubKey()}},
		Locktime:        vtxoTreeExpiry,
	}).Script()
	sweepRoot      = txscript.NewBaseTapLeaf(sweepScript).TapHash()
	receiverCounts = []int{1, 2, 20, 128}
)

func TestBuildAndSignVtxoTree(t *testing.T) {
	t.Parallel()

	for _, tc := range generateTestCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			sharedOutputScript, sharedOutputAmount, err := bitcointree.CraftSharedOutput(
				tc.receivers,
				minRelayFee,
				sweepRoot[:],
			)
			require.NoError(t, err)
			require.NotNil(t, sharedOutputScript)

			vtxoTree, err := bitcointree.BuildVtxoTree(
				&wire.OutPoint{
					Hash:  *testTxid,
					Index: 0,
				},
				tc.receivers,
				minRelayFee,
				sweepRoot[:],
				vtxoTreeExpiry,
			)
			require.NoError(t, err)

			serverCoordinator, err := bitcointree.NewTreeCoordinatorSession(
				sharedOutputAmount,
				vtxoTree,
				sweepRoot[:],
			)
			require.NoError(t, err)

			// Cceate signer sessions for each receivers
			signerSessions := make(map[*btcec.PublicKey]bitcointree.SignerSession)
			for _, prvkey := range tc.privKeys {
				session := bitcointree.NewTreeSignerSession(prvkey)
				err := session.Init(sweepRoot[:], sharedOutputAmount, vtxoTree)
				require.NoError(t, err)
				signerSessions[prvkey.PubKey()] = session
			}

			// Create server's signer session
			serverSession := bitcointree.NewTreeSignerSession(serverPrivKey)
			err = serverSession.Init(sweepRoot[:], sharedOutputAmount, vtxoTree)
			require.NoError(t, err)
			signerSessions[serverPrivKey.PubKey()] = serverSession

			// generate nonces from all signers
			for pubkey, session := range signerSessions {
				nonces, err := session.GetNonces()
				require.NoError(t, err)
				var encodedNonces bytes.Buffer
				err = nonces.Encode(&encodedNonces)
				require.NoError(t, err)
				decodedNonces, err := bitcointree.DecodeNonces(&encodedNonces)
				require.NoError(t, err)
				for i, nonceRow := range nonces {
					for j, nonce := range nonceRow {
						require.Equal(t, nonce, decodedNonces[i][j])
					}
				}

				serverCoordinator.AddNonce(pubkey, nonces)
			}

			aggregatedNonce, err := serverCoordinator.AggregateNonces()
			require.NoError(t, err)

			// set the aggregated nonces for all signers sessions
			for _, session := range signerSessions {
				session.SetAggregatedNonces(aggregatedNonce)
			}

			// get signatures from all signers sessions
			for pubkey, session := range signerSessions {
				sig, err := session.Sign()
				require.NoError(t, err)
				require.NotNil(t, sig)
				var encodedSig bytes.Buffer
				err = sig.Encode(&encodedSig)
				require.NoError(t, err)
				decodedSig, err := bitcointree.DecodeSignatures(&encodedSig)
				require.NoError(t, err)
				for i, sigRow := range sig {
					for j, sig := range sigRow {
						if sig == nil {
							require.Nil(t, decodedSig[i][j])
						} else {
							require.Equal(t, sig.S, decodedSig[i][j].S)
						}
					}
				}

				serverCoordinator.AddSig(pubkey, sig)
			}

			// aggregate signatures
			signedTree, err := serverCoordinator.SignTree()
			require.NoError(t, err)
			require.NotNil(t, signedTree)
			// validate signatures
			err = bitcointree.ValidateTreeSigs(
				sweepRoot[:],
				sharedOutputAmount,
				signedTree,
			)
			require.NoError(t, err)
		})
	}
}

type testCase struct {
	name      string
	receivers []tree.VtxoLeaf
	privKeys  []*secp256k1.PrivateKey
}

func generateReceiversFixture(count int) ([]tree.VtxoLeaf, []*secp256k1.PrivateKey, error) {
	receivers := make([]tree.VtxoLeaf, 0, count)
	privKeys := make([]*secp256k1.PrivateKey, 0, count)
	for i := 0; i < count; i++ {
		prvkey, err := secp256k1.GeneratePrivateKey()
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

func generateTestCases(t *testing.T) []testCase {
	testCases := make([]testCase, 0)
	for _, count := range receiverCounts {
		receivers, privKeys, err := generateReceiversFixture(count)
		require.NoError(t, err)
		// add mixed types test case if count is between 2 and 32
		if count > 1 && count < 32 {
			testCases = append(testCases, testCase{
				name:      fmt.Sprintf("%d receivers Mixed Signing Types", len(receivers)),
				receivers: withMixedSigningTypes(receivers),
				privKeys:  privKeys,
			})
		}

		// add SignAll test case if count is less than 32
		if count < 32 {
			testCases = append(testCases, testCase{
				name:      fmt.Sprintf("%d receivers SignAll", len(receivers)),
				receivers: withSigningType(tree.SignAll, receivers),
				privKeys:  privKeys,
			})
		}

		// always add SignBranch test case
		testCases = append(testCases, testCase{
			name:      fmt.Sprintf("%d receivers SignBranch", len(receivers)),
			receivers: withSigningType(tree.SignBranch, receivers),
			privKeys:  privKeys,
		})
	}
	return testCases
}
