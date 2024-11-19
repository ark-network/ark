package txbuilder_test

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/bitcointree"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/ark-network/ark/server/internal/core/ports"
	txbuilder "github.com/ark-network/ark/server/internal/infrastructure/tx-builder/covenantless"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const (
	testingKey        = "020000000000000000000000000000000000000000000000000000000000000001"
	connectorAddress  = "bc1py00yhcjpcj0k0sqra0etq0u3yy0purmspppsw0shyzyfe8c83tmq5h6kc2"
	forfeitAddress    = "bc1py00yhcjpcj0k0sqra0etq0u3yy0purmspppsw0shyzyfe8c83tmq5h6kc2"
	changeAddress     = "bcrt1qhhq55mut9easvrncy4se8q6vg3crlug7yj4j56"
	roundLifetime     = int64(1209344)
	boardingExitDelay = int64(512)
	minRelayFeeRate   = 3
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

func TestBuildPoolTx(t *testing.T) {
	builder := txbuilder.NewTxBuilder(
		wallet, common.Bitcoin, roundLifetime, boardingExitDelay,
	)

	fixtures, err := parsePoolTxFixtures()
	require.NoError(t, err)
	require.NotEmpty(t, fixtures)

	if len(fixtures.Valid) > 0 {
		t.Run("valid", func(t *testing.T) {
			for _, f := range fixtures.Valid {
				cosigners := make([]*secp256k1.PublicKey, 0)
				for range f.Payments {
					randKey, err := secp256k1.GeneratePrivateKey()
					require.NoError(t, err)

					cosigners = append(cosigners, randKey.PubKey())
				}

				poolTx, congestionTree, connAddr, _, err := builder.BuildRoundTx(
					pubkey, f.Payments, []ports.BoardingInput{}, []domain.Round{}, cosigners...,
				)
				require.NoError(t, err)
				require.NotEmpty(t, poolTx)
				require.NotEmpty(t, congestionTree)
				require.Equal(t, connectorAddress, connAddr)
				require.Equal(t, f.ExpectedNumOfNodes, congestionTree.NumberOfNodes())
				require.Len(t, congestionTree.Leaves(), f.ExpectedNumOfLeaves)

				err = bitcointree.ValidateCongestionTree(
					congestionTree, poolTx, pubkey, roundLifetime,
				)
				require.NoError(t, err)
			}
		})
	}

	if len(fixtures.Invalid) > 0 {
		t.Run("invalid", func(t *testing.T) {
			for _, f := range fixtures.Invalid {
				poolTx, congestionTree, connAddr, _, err := builder.BuildRoundTx(
					pubkey, f.Payments, []ports.BoardingInput{}, []domain.Round{},
				)
				require.EqualError(t, err, f.ExpectedErr)
				require.Empty(t, poolTx)
				require.Empty(t, connAddr)
				require.Empty(t, congestionTree)
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
