package txbuilder_test

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/internal/core/domain"
	"github.com/ark-network/ark/internal/core/ports"
	txbuilder "github.com/ark-network/ark/internal/infrastructure/tx-builder/covenant"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/vulpemventures/go-elements/network"
	"github.com/vulpemventures/go-elements/psetv2"
)

const (
	testingKey    = "apub1qgvdtj5ttpuhkldavhq8thtm5auyk0ec4dcmrfdgu0u5hgp9we22v3hrs4x"
	minRelayFee   = uint64(30)
	roundLifetime = int64(1209344)
)

var (
	wallet *mockedWallet
	pubkey *secp256k1.PublicKey
)

func TestMain(m *testing.M) {
	wallet = &mockedWallet{}
	wallet.On("EstimateFees", mock.Anything, mock.Anything).
		Return(uint64(100), nil)
	wallet.On("SelectUtxos", mock.Anything, mock.Anything, mock.Anything).
		Return(randomInput, uint64(0), nil)

	_, pubkey, _ = common.DecodePubKey(testingKey)

	os.Exit(m.Run())
}

func TestBuildPoolTx(t *testing.T) {
	builder := txbuilder.NewTxBuilder(wallet, network.Liquid)

	fixtures, err := parsePoolTxFixtures()
	require.NoError(t, err)
	require.NotEmpty(t, fixtures)

	if len(fixtures.Valid) > 0 {
		t.Run("valid", func(t *testing.T) {
			for _, f := range fixtures.Valid {
				poolTx, congestionTree, err := builder.BuildPoolTx(pubkey, f.Payments, minRelayFee)
				require.NoError(t, err)
				require.NotEmpty(t, poolTx)
				require.NotEmpty(t, congestionTree)
				require.Equal(t, f.ExpectedNumOfNodes, congestionTree.NumberOfNodes())
				require.Len(t, congestionTree.Leaves(), f.ExpectedNumOfLeaves)

				err = tree.ValidateCongestionTree(congestionTree, poolTx, pubkey, roundLifetime)
				require.NoError(t, err)
			}
		})
	}

	if len(fixtures.Invalid) > 0 {
		t.Run("invalid", func(t *testing.T) {
			for _, f := range fixtures.Invalid {
				poolTx, congestionTree, err := builder.BuildPoolTx(pubkey, f.Payments, minRelayFee)
				require.EqualError(t, err, f.ExpectedErr)
				require.Empty(t, poolTx)
				require.Empty(t, congestionTree)
			}
		})
	}
}

func TestBuildForfeitTxs(t *testing.T) {
	builder := txbuilder.NewTxBuilder(wallet, network.Liquid)

	fixtures, err := parseForfeitTxsFixtures()
	require.NoError(t, err)
	require.NotEmpty(t, fixtures)

	if len(fixtures.Valid) > 0 {
		t.Run("valid", func(t *testing.T) {
			for _, f := range fixtures.Valid {
				connectors, forfeitTxs, err := builder.BuildForfeitTxs(
					pubkey, f.PoolTx, f.Payments,
				)
				require.NoError(t, err)
				require.Len(t, connectors, f.ExpectedNumOfConnectors)
				require.Len(t, forfeitTxs, f.ExpectedNumOfForfeitTxs)

				expectedInputTxid := f.PoolTxid
				// Verify the chain of connectors
				for _, connector := range connectors {
					tx, err := psetv2.NewPsetFromBase64(connector)
					require.NoError(t, err)
					require.NotNil(t, tx)

					require.Len(t, tx.Inputs, 1)
					require.Len(t, tx.Outputs, 2)

					inputTxid := chainhash.Hash(tx.Inputs[0].PreviousTxid).String()
					require.Equal(t, expectedInputTxid, inputTxid)
					require.Equal(t, 1, int(tx.Inputs[0].PreviousTxIndex))

					expectedInputTxid = getTxid(tx)
				}

				// decode and check forfeit txs
				for _, forfeitTx := range forfeitTxs {
					tx, err := psetv2.NewPsetFromBase64(forfeitTx)
					require.NoError(t, err)
					require.Len(t, tx.Inputs, 2)
					require.Len(t, tx.Outputs, 2)
				}
			}
		})
	}

	if len(fixtures.Invalid) > 0 {
		t.Run("invalid", func(t *testing.T) {
			for _, f := range fixtures.Invalid {
				connectors, forfeitTxs, err := builder.BuildForfeitTxs(
					pubkey, f.PoolTx, f.Payments,
				)
				require.EqualError(t, err, f.ExpectedErr)
				require.Empty(t, connectors)
				require.Empty(t, forfeitTxs)
			}
		})
	}
}

func randomInput() []ports.TxInput {
	txid := randomHex(32)
	input := &mockedInput{}
	input.On("GetAsset").Return("5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225")
	input.On("GetValue").Return(uint64(1000))
	input.On("GetScript").Return("a914ea9f486e82efb3dd83a69fd96e3f0113757da03c87")
	input.On("GetTxid").Return(txid)
	input.On("GetIndex").Return(uint32(0))

	return []ports.TxInput{input}
}

func randomHex(len int) string {
	buf := make([]byte, len)
	// nolint
	rand.Read(buf)
	return hex.EncodeToString(buf)
}

type poolTxFixtures struct {
	Valid []struct {
		Payments            []domain.Payment
		ExpectedNumOfNodes  int
		ExpectedNumOfLeaves int
	}
	Invalid []struct {
		Payments    []domain.Payment
		ExpectedErr string
	}
}

func parsePoolTxFixtures() (*poolTxFixtures, error) {
	file, err := os.ReadFile("testdata/fixtures.json")
	if err != nil {
		return nil, err
	}
	v := map[string]interface{}{}
	if err := json.Unmarshal(file, &v); err != nil {
		return nil, err
	}

	vv := v["buildPoolTx"].(map[string]interface{})
	file, _ = json.Marshal(vv)
	var fixtures poolTxFixtures
	if err := json.Unmarshal(file, &fixtures); err != nil {
		return nil, err
	}

	return &fixtures, nil
}

type forfeitTxsFixtures struct {
	Valid []struct {
		Payments                []domain.Payment
		ExpectedNumOfConnectors int
		ExpectedNumOfForfeitTxs int
		PoolTx                  string
		PoolTxid                string
	}
	Invalid []struct {
		Payments    []domain.Payment
		ExpectedErr string
		PoolTx      string
	}
}

func parseForfeitTxsFixtures() (*forfeitTxsFixtures, error) {
	file, err := os.ReadFile("testdata/fixtures.json")
	if err != nil {
		return nil, err
	}
	v := map[string]interface{}{}
	if err := json.Unmarshal(file, &v); err != nil {
		return nil, err
	}

	vv := v["buildForfeitTxs"].(map[string]interface{})
	file, _ = json.Marshal(vv)
	var fixtures forfeitTxsFixtures
	if err := json.Unmarshal(file, &fixtures); err != nil {
		return nil, err
	}

	return &fixtures, nil
}

func getTxid(tx *psetv2.Pset) string {
	utx, _ := tx.UnsignedTx()
	return utx.TxHash().String()
}
