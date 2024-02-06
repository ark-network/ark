package txbuilder_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/internal/core/domain"
	"github.com/ark-network/ark/internal/core/ports"
	txbuilder "github.com/ark-network/ark/internal/infrastructure/tx-builder/dummy"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"
	"github.com/vulpemventures/go-elements/network"
	"github.com/vulpemventures/go-elements/psetv2"
)

const (
	testingKey = "apub1qgvdtj5ttpuhkldavhq8thtm5auyk0ec4dcmrfdgu0u5hgp9we22v3hrs4x"
	fakePoolTx = "cHNldP8BAgQCAAAAAQQBAQEFAQMBBgEDAfsEAgAAAAABDiDk7dXxh4KQzgLO8i1ABtaLCe4aPL12GVhN1E9zM1ePLwEPBAAAAAABEAT/////AAEDCOgDAAAAAAAAAQQWABSNnpy01UJqd99eTg2M1IpdKId11gf8BHBzZXQCICWyUQcOKcoZBDzzPM1zJOLdqwPsxK4LXnfE/A5c9slaB/wEcHNldAgEAAAAAAABAwh4BQAAAAAAAAEEFgAUjZ6ctNVCanffXk4NjNSKXSiHddYH/ARwc2V0AiAlslEHDinKGQQ88zzNcyTi3asD7MSuC153xPwOXPbJWgf8BHBzZXQIBAAAAAAAAQMI9AEAAAAAAAABBAAH/ARwc2V0AiAlslEHDinKGQQ88zzNcyTi3asD7MSuC153xPwOXPbJWgf8BHBzZXQIBAAAAAAA"
)

type input struct {
	txid string
	vout uint32
}

func (i *input) GetTxid() string {
	return i.txid
}

func (i *input) GetIndex() uint32 {
	return i.vout
}

func (i *input) GetScript() string {
	return "a914ea9f486e82efb3dd83a69fd96e3f0113757da03c87"
}

func (i *input) GetAsset() string {
	return "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225"
}

func (i *input) GetValue() uint64 {
	return 1000
}

type mockedWalletService struct{}

// BroadcastTransaction implements ports.WalletService.
func (*mockedWalletService) BroadcastTransaction(ctx context.Context, txHex string) (string, error) {
	panic("unimplemented")
}

// Close implements ports.WalletService.
func (*mockedWalletService) Close() {
	panic("unimplemented")
}

// DeriveAddresses implements ports.WalletService.
func (*mockedWalletService) DeriveAddresses(ctx context.Context, num int) ([]string, error) {
	panic("unimplemented")
}

// GetPubkey implements ports.WalletService.
func (*mockedWalletService) GetPubkey(ctx context.Context) (*secp256k1.PublicKey, error) {
	panic("unimplemented")
}

// SignPset implements ports.WalletService.
func (*mockedWalletService) SignPset(ctx context.Context, pset string, extractRawTx bool) (string, error) {
	panic("unimplemented")
}

// Status implements ports.WalletService.
func (*mockedWalletService) Status(ctx context.Context) (ports.WalletStatus, error) {
	panic("unimplemented")
}

func (*mockedWalletService) SelectUtxos(ctx context.Context, asset string, amount uint64) ([]ports.TxInput, uint64, error) {
	// random txid
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return nil, 0, err
	}
	fakeInput := input{
		txid: hex.EncodeToString(bytes),
		vout: 0,
	}

	return []ports.TxInput{&fakeInput}, 0, nil
}

func (*mockedWalletService) EstimateFees(ctx context.Context, pset string) (uint64, error) {
	return 100, nil
}

func TestBuildCongestionTree(t *testing.T) {
	builder := txbuilder.NewTxBuilder(&mockedWalletService{}, network.Liquid)

	fixtures := []struct {
		payments          []domain.Payment
		expectedNodesNum  int // 2*len(receivers)-1
		expectedLeavesNum int
	}{
		{
			payments: []domain.Payment{
				{
					Id: "0",
					Inputs: []domain.Vtxo{
						{
							VtxoKey: domain.VtxoKey{
								Txid: "fd68e3c5796cc7db0a8036d486d5f625b6b2f2c014810ac020e1ac23e82c59d6",
								VOut: 0,
							},
							Receiver: domain.Receiver{
								Pubkey: "020000000000000000000000000000000000000000000000000000000000000002",
								Amount: 600,
							},
						},
					},
					Receivers: []domain.Receiver{
						{
							Pubkey: "020000000000000000000000000000000000000000000000000000000000000002",
							Amount: 600,
						},
						{
							Pubkey: "020000000000000000000000000000000000000000000000000000000000000002",
							Amount: 400,
						},
					},
				},
			},
			expectedNodesNum:  3,
			expectedLeavesNum: 2,
		},
		{
			payments: []domain.Payment{
				{
					Id: "0",
					Inputs: []domain.Vtxo{
						{
							VtxoKey: domain.VtxoKey{
								Txid: "fd68e3c5796cc7db0a8036d486d5f625b6b2f2c014810ac020e1ac23e82c59d6",
								VOut: 0,
							},
							Receiver: domain.Receiver{
								Pubkey: "020000000000000000000000000000000000000000000000000000000000000002",
								Amount: 600,
							},
						},
					},
					Receivers: []domain.Receiver{
						{
							Pubkey: "020000000000000000000000000000000000000000000000000000000000000002",
							Amount: 600,
						},
						{
							Pubkey: "020000000000000000000000000000000000000000000000000000000000000002",
							Amount: 400,
						},
					},
				},
				{
					Id: "0",
					Inputs: []domain.Vtxo{
						{
							VtxoKey: domain.VtxoKey{
								Txid: "fd68e3c5796cc7db0a8036d486d5f625b6b2f2c014810ac020e1ac23e82c59d6",
								VOut: 0,
							},
							Receiver: domain.Receiver{
								Pubkey: "020000000000000000000000000000000000000000000000000000000000000002",
								Amount: 600,
							},
						},
					},
					Receivers: []domain.Receiver{
						{
							Pubkey: "020000000000000000000000000000000000000000000000000000000000000002",
							Amount: 600,
						},
						{
							Pubkey: "020000000000000000000000000000000000000000000000000000000000000002",
							Amount: 400,
						},
					},
				},
				{
					Id: "0",
					Inputs: []domain.Vtxo{
						{
							VtxoKey: domain.VtxoKey{
								Txid: "fd68e3c5796cc7db0a8036d486d5f625b6b2f2c014810ac020e1ac23e82c59d6",
								VOut: 0,
							},
							Receiver: domain.Receiver{
								Pubkey: "020000000000000000000000000000000000000000000000000000000000000002",
								Amount: 600,
							},
						},
					},
					Receivers: []domain.Receiver{
						{
							Pubkey: "020000000000000000000000000000000000000000000000000000000000000002",
							Amount: 600,
						},
						{
							Pubkey: "020000000000000000000000000000000000000000000000000000000000000002",
							Amount: 400,
						},
					},
				},
			},
			expectedNodesNum:  11,
			expectedLeavesNum: 6,
		},
	}

	_, key, err := common.DecodePubKey(testingKey)
	require.NoError(t, err)
	require.NotNil(t, key)

	for _, f := range fixtures {
		poolTx, tree, err := builder.BuildPoolTx(key, f.payments, 30)

		require.NoError(t, err)
		require.Equal(t, f.expectedNodesNum, tree.NumberOfNodes())
		require.Len(t, tree.Leaves(), f.expectedLeavesNum)

		poolPset, err := psetv2.NewPsetFromBase64(poolTx)
		require.NoError(t, err)

		poolTxUnsigned, err := poolPset.UnsignedTx()
		require.NoError(t, err)

		poolTxID := poolTxUnsigned.TxHash().String()

		// check the root
		require.Len(t, tree[0], 1)
		require.Equal(t, poolTxID, tree[0][0].ParentTxid)

		// check the leaves
		for _, leaf := range tree.Leaves() {
			pset, err := psetv2.NewPsetFromBase64(leaf.Tx)
			require.NoError(t, err)

			require.Len(t, pset.Inputs, 1)
			require.Len(t, pset.Outputs, 1)

			inputTxID := chainhash.Hash(pset.Inputs[0].PreviousTxid).String()
			require.Equal(t, leaf.ParentTxid, inputTxID)
		}

		// check the nodes
		for _, level := range tree[:len(tree)-2] {
			for _, node := range level {
				pset, err := psetv2.NewPsetFromBase64(node.Tx)
				require.NoError(t, err)

				require.Len(t, pset.Inputs, 1)
				require.Len(t, pset.Outputs, 2)

				inputTxID := chainhash.Hash(pset.Inputs[0].PreviousTxid).String()
				require.Equal(t, node.ParentTxid, inputTxID)

				children := tree.Children(node.Txid)
				require.Len(t, children, 2)
			}
		}
	}
}

func TestBuildForfeitTxs(t *testing.T) {
	builder := txbuilder.NewTxBuilder(&mockedWalletService{}, network.Liquid)

	poolPset, err := psetv2.NewPsetFromBase64(fakePoolTx)
	require.NoError(t, err)

	poolTxUnsigned, err := poolPset.UnsignedTx()
	require.NoError(t, err)

	poolTxID := poolTxUnsigned.TxHash().String()

	fixtures := []struct {
		payments                []domain.Payment
		expectedNumOfForfeitTxs int
		expectedNumOfConnectors int
	}{
		{
			payments: []domain.Payment{
				{
					Id: "0",
					Inputs: []domain.Vtxo{
						{
							VtxoKey: domain.VtxoKey{
								Txid: "fd68e3c5796cc7db0a8036d486d5f625b6b2f2c014810ac020e1ac23e82c59d6",
								VOut: 0,
							},
							Receiver: domain.Receiver{
								Pubkey: "020000000000000000000000000000000000000000000000000000000000000002",
								Amount: 600,
							},
						},
						{
							VtxoKey: domain.VtxoKey{
								Txid: "fd68e3c5796cc7db0a8036d486d5f625b6b2f2c014810ac020e1ac23e82c59d6",
								VOut: 1,
							},
							Receiver: domain.Receiver{
								Pubkey: "020000000000000000000000000000000000000000000000000000000000000002",
								Amount: 400,
							},
						},
					},
					Receivers: []domain.Receiver{
						{
							Pubkey: "020000000000000000000000000000000000000000000000000000000000000002",
							Amount: 600,
						},
						{
							Pubkey: "020000000000000000000000000000000000000000000000000000000000000002",
							Amount: 400,
						},
					},
				},
			},
			expectedNumOfForfeitTxs: 4,
			expectedNumOfConnectors: 1,
		},
	}

	_, key, err := common.DecodePubKey(testingKey)
	require.NoError(t, err)
	require.NotNil(t, key)

	for _, f := range fixtures {
		connectors, forfeitTxs, err := builder.BuildForfeitTxs(
			key, fakePoolTx, f.payments,
		)
		require.NoError(t, err)
		require.Len(t, connectors, f.expectedNumOfConnectors)
		require.Len(t, forfeitTxs, f.expectedNumOfForfeitTxs)

		// decode and check connectors
		connectorsPsets := make([]*psetv2.Pset, 0, f.expectedNumOfConnectors)
		for _, pset := range connectors {
			p, err := psetv2.NewPsetFromBase64(pset)
			require.NoError(t, err)
			connectorsPsets = append(connectorsPsets, p)
		}

		for i, pset := range connectorsPsets {
			require.Len(t, pset.Inputs, 1)
			require.Len(t, pset.Outputs, 2)

			expectedInputTxid := poolTxID
			expectedInputVout := uint32(1)
			if i > 0 {
				tx, err := connectorsPsets[i-1].UnsignedTx()
				require.NoError(t, err)
				require.NotNil(t, tx)
				expectedInputTxid = tx.TxHash().String()
			}

			inputTxid := chainhash.Hash(pset.Inputs[0].PreviousTxid).String()
			require.Equal(t, expectedInputTxid, inputTxid)
			require.Equal(t, expectedInputVout, pset.Inputs[0].PreviousTxIndex)
		}

		// decode and check forfeit txs
		forfeitTxsPsets := make([]*psetv2.Pset, 0, f.expectedNumOfForfeitTxs)
		for _, pset := range forfeitTxs {
			p, err := psetv2.NewPsetFromBase64(pset)
			require.NoError(t, err)
			forfeitTxsPsets = append(forfeitTxsPsets, p)
		}

		// each forfeit tx should have 2 inputs and 2 outputs
		for _, pset := range forfeitTxsPsets {
			require.Len(t, pset.Inputs, 2)
			require.Len(t, pset.Outputs, 1)
		}
	}
}
