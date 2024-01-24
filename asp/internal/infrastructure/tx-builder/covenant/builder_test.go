package txbuilder_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/internal/core/domain"
	"github.com/ark-network/ark/internal/core/ports"
	txbuilder "github.com/ark-network/ark/internal/infrastructure/tx-builder/covenant"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"
	"github.com/vulpemventures/go-elements/network"
	"github.com/vulpemventures/go-elements/payment"
	"github.com/vulpemventures/go-elements/psetv2"
)

const (
	testingKey = "apub1qgvdtj5ttpuhkldavhq8thtm5auyk0ec4dcmrfdgu0u5hgp9we22v3hrs4x"
)

func createTestPoolTx(sharedOutputAmount, numberOfInputs uint64) (string, error) {
	_, key, err := common.DecodePubKey(testingKey)
	if err != nil {
		return "", err
	}

	payment := payment.FromPublicKey(key, &network.Testnet, nil)
	script := payment.WitnessScript

	pset, err := psetv2.New(nil, nil, nil)
	if err != nil {
		return "", err
	}

	updater, err := psetv2.NewUpdater(pset)
	if err != nil {
		return "", err
	}

	err = updater.AddInputs([]psetv2.InputArgs{
		{
			Txid:    "2f8f5733734fd44d581976bd3c1aee098bd606402df2ce02ce908287f1d5ede4",
			TxIndex: 0,
		},
	})
	if err != nil {
		return "", err
	}

	connectorsAmount := numberOfInputs*450 + 500

	err = updater.AddOutputs([]psetv2.OutputArgs{
		{
			Asset:  network.Regtest.AssetID,
			Amount: sharedOutputAmount,
			Script: script,
		},
		{
			Asset:  network.Regtest.AssetID,
			Amount: connectorsAmount,
			Script: script,
		},
		{
			Asset:  network.Regtest.AssetID,
			Amount: 500,
		},
	})
	if err != nil {
		return "", err
	}

	return pset.ToBase64()
}

type mockedWalletService struct{}

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
	builder := txbuilder.NewTxBuilder(network.Liquid)

	fixtures := []struct {
		payments          []domain.Payment
		expectedNodesNum  int // 2*len(receivers) -1
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
								Amount: 1100,
							},
						},
					},
					Receivers: []domain.Receiver{
						{
							Pubkey: "020000000000000000000000000000000000000000000000000000000000000002",
							Amount: 1100,
						},
					},
				},
			},
			expectedNodesNum:  1,
			expectedLeavesNum: 1,
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
								Amount: 1100,
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
							Amount: 500,
						},
					},
				},
			},
			expectedNodesNum:  1,
			expectedLeavesNum: 1,
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
								Amount: 1100,
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
							Amount: 500,
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
								Amount: 1100,
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
							Amount: 500,
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
								Amount: 1100,
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
							Amount: 500,
						},
					},
				},
			},
			expectedNodesNum:  5,
			expectedLeavesNum: 3,
		}, {
			payments: []domain.Payment{
				{
					Id: "a242cdd8-f3d5-46c0-ae98-94135a2bee3f",
					Inputs: []domain.Vtxo{
						{
							VtxoKey: domain.VtxoKey{
								Txid: "755c820771284d85ea4bbcc246565b4eddadc44237a7e57a0f9cb78a840d1d41",
								VOut: 0,
							},
							Receiver: domain.Receiver{
								Pubkey: "02c87e5c1758df5ad42a918ec507b6e8dfcdcebf22f64f58eb4ad5804257d658a5",
								Amount: 1000,
							},
						},
						{
							VtxoKey: domain.VtxoKey{
								Txid: "66a0df86fcdeb84b8877adfe0b2c556dba30305d72ddbd4c49355f6930355357",
								VOut: 0,
							},
							Receiver: domain.Receiver{
								Pubkey: "02c87e5c1758df5ad42a918ec507b6e8dfcdcebf22f64f58eb4ad5804257d658a5",
								Amount: 1000,
							},
						},
						{
							VtxoKey: domain.VtxoKey{
								Txid: "9913159bc7aa493ca53cbb9cbc88f97ba01137c814009dc7ef520c3fafc67909",
								VOut: 1,
							},
							Receiver: domain.Receiver{
								Pubkey: "02c87e5c1758df5ad42a918ec507b6e8dfcdcebf22f64f58eb4ad5804257d658a5",
								Amount: 500,
							},
						},
						{
							VtxoKey: domain.VtxoKey{
								Txid: "5e10e77a7cdedc153be5193a4b6055a7802706ded4f2a9efefe86ed2f9a6ae60",
								VOut: 0,
							},
							Receiver: domain.Receiver{
								Pubkey: "02c87e5c1758df5ad42a918ec507b6e8dfcdcebf22f64f58eb4ad5804257d658a5",
								Amount: 1000,
							},
						},
						{
							VtxoKey: domain.VtxoKey{
								Txid: "5e10e77a7cdedc153be5193a4b6055a7802706ded4f2a9efefe86ed2f9a6ae60",
								VOut: 1,
							},
							Receiver: domain.Receiver{
								Pubkey: "02c87e5c1758df5ad42a918ec507b6e8dfcdcebf22f64f58eb4ad5804257d658a5",
								Amount: 1000,
							},
						},
					},
					Receivers: []domain.Receiver{
						{
							Pubkey: "02c87e5c1758df5ad42a918ec507b6e8dfcdcebf22f64f58eb4ad5804257d658a5",
							Amount: 1000,
						},
						{
							Pubkey: "02c87e5c1758df5ad42a918ec507b6e8dfcdcebf22f64f58eb4ad5804257d658a5",
							Amount: 1000,
						},
						{
							Pubkey: "02c87e5c1758df5ad42a918ec507b6e8dfcdcebf22f64f58eb4ad5804257d658a5",
							Amount: 1000,
						},
						{
							Pubkey: "02c87e5c1758df5ad42a918ec507b6e8dfcdcebf22f64f58eb4ad5804257d658a5",
							Amount: 1000,
						},
						{
							Pubkey: "02c87e5c1758df5ad42a918ec507b6e8dfcdcebf22f64f58eb4ad5804257d658a5",
							Amount: 500,
						},
					},
				},
			},
			expectedNodesNum:  4,
			expectedLeavesNum: 3,
		},
	}

	_, key, err := common.DecodePubKey(testingKey)
	require.NoError(t, err)
	require.NotNil(t, key)

	for _, f := range fixtures {
		poolTx, congestionTree, err := builder.BuildPoolTx(key, &mockedWalletService{}, f.payments, 30)
		require.NoError(t, err)
		require.Equal(t, f.expectedNodesNum, congestionTree.NumberOfNodes())
		require.Len(t, congestionTree.Leaves(), f.expectedLeavesNum)

		// check that the pool tx has the right number of inputs and outputs
		err = tree.ValidateCongestionTree(
			congestionTree,
			poolTx,
			key,
			1209344, // 2 weeks - 8 minutes
		)
		require.NoError(t, err)
	}
}

func TestBuildForfeitTxs(t *testing.T) {
	builder := txbuilder.NewTxBuilder(network.Liquid)

	// TODO: replace with fixture.
	poolTxBase64, err := createTestPoolTx(1000, 2)
	require.NoError(t, err)

	poolTx, err := psetv2.NewPsetFromBase64(poolTxBase64)
	require.NoError(t, err)

	utx, err := poolTx.UnsignedTx()
	require.NoError(t, err)

	poolTxid := utx.TxHash().String()

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
								Amount: 500,
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
							Amount: 500,
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
			key, poolTxBase64, f.payments,
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

			expectedInputTxid := poolTxid
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
			require.Len(t, pset.Outputs, 2)
		}
	}
}
