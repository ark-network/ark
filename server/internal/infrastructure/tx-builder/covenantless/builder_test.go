package txbuilder_test

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/bitcointree"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/ark-network/ark/server/internal/core/ports"
	txbuilder "github.com/ark-network/ark/server/internal/infrastructure/tx-builder/covenantless"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const (
	testingKey       = "020000000000000000000000000000000000000000000000000000000000000001"
	connectorAddress = "bc1py00yhcjpcj0k0sqra0etq0u3yy0purmspppsw0shyzyfe8c83tmq5h6kc2"
	forfeitAddress   = "bc1py00yhcjpcj0k0sqra0etq0u3yy0purmspppsw0shyzyfe8c83tmq5h6kc2"
	changeAddress    = "bcrt1qhhq55mut9easvrncy4se8q6vg3crlug7yj4j56"
	minRelayFeeRate  = 3
)

var (
	wallet *mockedWallet
	pubkey *secp256k1.PublicKey

	vtxoTreeExpiry    = common.RelativeLocktime{Type: common.LocktimeTypeSecond, Value: 1209344}
	boardingExitDelay = common.RelativeLocktime{Type: common.LocktimeTypeSecond, Value: 512}
)

func TestMain(m *testing.M) {
	wallet = &mockedWallet{}
	wallet.On("EstimateFees", mock.Anything, mock.Anything).
		Return(uint64(100), nil)
	wallet.On("SelectUtxos", mock.Anything, mock.Anything, mock.Anything).
		Return(randomInput, uint64(1000), nil)
	wallet.On("DeriveAddresses", mock.Anything, mock.Anything).
		Return([]string{changeAddress}, nil)
	wallet.On("DeriveConnectorAddress", mock.Anything).
		Return(connectorAddress, nil)
	wallet.On("MinRelayFee", mock.Anything, mock.Anything).
		Return(uint64(30), nil)
	wallet.On("GetDustAmount", mock.Anything).
		Return(uint64(1000), nil)
	wallet.On("GetForfeitAddress", mock.Anything).
		Return(forfeitAddress, nil)

	pubkeyBytes, _ := hex.DecodeString(testingKey)
	pubkey, _ = secp256k1.ParsePubKey(pubkeyBytes)

	os.Exit(m.Run())
}

func TestBuildRoundTx(t *testing.T) {
	builder := txbuilder.NewTxBuilder(
		wallet, common.Bitcoin, vtxoTreeExpiry, boardingExitDelay,
	)

	fixtures, err := parseRoundTxFixtures()
	require.NoError(t, err)
	require.NotEmpty(t, fixtures)

	if len(fixtures.Valid) > 0 {
		t.Run("valid", func(t *testing.T) {
			for _, f := range fixtures.Valid {
				musig2Data := make([]*tree.Musig2, 0)

				for range f.Requests {
					randKey, err := secp256k1.GeneratePrivateKey()
					require.NoError(t, err)

					musig2Data = append(musig2Data, &tree.Musig2{
						CosignersPublicKeys: []string{
							hex.EncodeToString(randKey.PubKey().SerializeCompressed()),
						},
						SigningType: 0,
					})
				}

				roundTx, vtxoTree, connAddr, _, err := builder.BuildRoundTx(
					pubkey, f.Requests, []ports.BoardingInput{}, []string{}, musig2Data,
				)
				require.NoError(t, err)
				require.NotEmpty(t, roundTx)
				require.NotEmpty(t, vtxoTree)
				require.Equal(t, connectorAddress, connAddr)
				require.Equal(t, f.ExpectedNumOfNodes, vtxoTree.NumberOfNodes())
				require.Len(t, vtxoTree.Leaves(), f.ExpectedNumOfLeaves)

				err = bitcointree.ValidateVtxoTree(
					vtxoTree, roundTx, pubkey, vtxoTreeExpiry,
				)
				require.NoError(t, err)
			}
		})
	}

	if len(fixtures.Invalid) > 0 {
		t.Run("invalid", func(t *testing.T) {
			for _, f := range fixtures.Invalid {
				musig2Data := make([]*tree.Musig2, 0)

				for range f.Requests {
					musig2Data = append(musig2Data, &tree.Musig2{
						CosignersPublicKeys: []string{
							hex.EncodeToString(pubkey.SerializeCompressed()),
						},
						SigningType: 0,
					})
				}

				roundTx, vtxoTree, connAddr, _, err := builder.BuildRoundTx(
					pubkey, f.Requests, []ports.BoardingInput{}, []string{}, musig2Data,
				)
				require.EqualError(t, err, f.ExpectedErr)
				require.Empty(t, roundTx)
				require.Empty(t, connAddr)
				require.Empty(t, vtxoTree)
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

type roundTxFixtures struct {
	Valid []struct {
		Requests            []domain.TxRequest
		ExpectedNumOfNodes  int
		ExpectedNumOfLeaves int
	}
	Invalid []struct {
		Requests    []domain.TxRequest
		ExpectedErr string
	}
}

func parseRoundTxFixtures() (*roundTxFixtures, error) {
	file, err := os.ReadFile("testdata/fixtures.json")
	if err != nil {
		return nil, err
	}
	v := map[string]interface{}{}
	if err := json.Unmarshal(file, &v); err != nil {
		return nil, err
	}

	vv := v["buildRoundTx"].(map[string]interface{})
	file, _ = json.Marshal(vv)
	var fixtures roundTxFixtures
	if err := json.Unmarshal(file, &fixtures); err != nil {
		return nil, err
	}

	return &fixtures, nil
}
