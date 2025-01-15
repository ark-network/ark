package bitcointree_test

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/bitcointree"
	"github.com/ark-network/ark/common/tree"
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

var lifetime = common.RelativeLocktime{Type: common.LocktimeTypeBlock, Value: 144}

var testTxid, _ = chainhash.NewHashFromStr("49f8664acc899be91902f8ade781b7eeb9cbe22bdd9efbc36e56195de21bcd12")

func TestRoundTripSignTree(t *testing.T) {
	t.Parallel()
	fixtures := parseFixtures(t)
	for i, f := range fixtures.Valid {
		t.Run(fmt.Sprintf("test %d", i), func(t *testing.T) {
			server, err := secp256k1.GeneratePrivateKey()
			require.NoError(t, err)

			sweepScript, err := (&tree.CSVMultisigClosure{
				MultisigClosure: tree.MultisigClosure{PubKeys: []*secp256k1.PublicKey{server.PubKey()}},
				Locktime:        lifetime,
			}).Script()
			require.NoError(t, err)

			sweepTapLeaf := txscript.NewBaseTapLeaf(sweepScript)
			sweepRoot := sweepTapLeaf.TapHash()

			receivers := make([]tree.VtxoLeaf, 0, len(f.Receivers))

			privKeys := make([]*secp256k1.PrivateKey, 0, len(receivers))
			for i, r := range castReceivers(f.Receivers) {
				receiver := r
				prvkey, err := secp256k1.GeneratePrivateKey()
				require.NoError(t, err)
				privKeys = append(privKeys, prvkey)

				receiver.SignersPublicKeys = []string{
					hex.EncodeToString(prvkey.PubKey().SerializeCompressed()),
				}
				if i%2 == 0 {
					receiver.Type = tree.SignAll
				} else {
					receiver.Type = tree.SignBranch
				}
				receivers = append(receivers, receiver)
			}

			_, sharedOutputAmount, err := bitcointree.CraftSharedOutput(
				receivers,
				minRelayFee,
				sweepRoot[:],
			)
			require.NoError(t, err)

			vtxoTree, err := bitcointree.BuildVtxoTree(
				&wire.OutPoint{
					Hash:  *testTxid,
					Index: 0,
				},
				receivers,
				minRelayFee,
				sweepRoot[:],
			)
			require.NoError(t, err)

			serverCoordinator, err := bitcointree.NewTreeCoordinatorSession(
				sharedOutputAmount,
				vtxoTree,
				sweepRoot[:],
			)
			require.NoError(t, err)

			// Create signer sessions for all cosigners
			signerSessions := make([]bitcointree.SignerSession, len(receivers))
			for i, prvkey := range privKeys {
				signerSessions[i], err = bitcointree.NewTreeSignerSession(prvkey, sharedOutputAmount, vtxoTree, sweepRoot[:])
				require.NoError(t, err)
			}

			// Get nonces from all signers
			for i, session := range signerSessions {
				nonces, err := session.GetNonces()
				require.NoError(t, err)
				serverCoordinator.AddNonce(privKeys[i].PubKey(), nonces)
			}

			aggregatedNonce, err := serverCoordinator.AggregateNonces()
			require.NoError(t, err)

			// Set keys and aggregated nonces for all signers
			for _, session := range signerSessions {
				session.SetAggregatedNonces(aggregatedNonce)
			}

			// Get signatures from all signers
			for i, session := range signerSessions {
				sig, err := session.Sign()
				require.NoError(t, err)
				serverCoordinator.AddSig(privKeys[i].PubKey(), sig)
			}

			signedTree, err := serverCoordinator.SignTree()
			require.NoError(t, err)

			err = bitcointree.ValidateTreeSigs(
				sweepRoot[:],
				sharedOutputAmount,
				signedTree,
			)
			require.NoError(t, err)
		})
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
