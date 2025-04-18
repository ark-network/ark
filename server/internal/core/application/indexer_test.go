package application

import (
	"context"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/stretchr/testify/assert"

	"github.com/ark-network/ark/server/internal/core/domain" // adapt for your project
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

//---------------------------------------------
// Test scenario:
//
//   LeafTx (outpoint = vtxoA)   [leaf, no RedeemTx]
//      \
//       \---> RedeemTx1 (inputs: A)  =>  produces vtxoB, vtxoC
//                     \
//                      \---> RedeemTx2 (inputs: B) => produces vtxoD, vtxoE
//                                     \
//                                      \---> RedeemTx3 (inputs: C, E) => produces vtxoF (final)
//---------------------------------------------

func TestBuildChain(t *testing.T) {
	//TODO: test more complex scenarios
	ctx := context.Background()

	//
	// 1) Build all the PSBTs needed
	//
	// Leaf: vtxoA is not pending => no RedeemTx. It's identified by (Txid="leafTx", VOut=0).
	// RedeemTx1 => references [ (leafTx,0) ].
	redeemTx1, redeemTx1ID, err := makePsbtReferencingMany([]domain.VtxoKey{
		{Txid: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", VOut: 0},
	})
	require.NoError(t, err)

	// RedeemTx2 => references [ (RedeemTx1,0) ] (i.e. vtxoB).
	redeemTx2, redeemTx2ID, err := makePsbtReferencingMany([]domain.VtxoKey{
		{Txid: redeemTx1ID, VOut: 0},
	})
	require.NoError(t, err)

	// RedeemTx3 => references [ (RedeemTx1,1), (RedeemTx2,1) ] (i.e. vtxoC, vtxoE).
	redeemTx3, redeemTx3ID, err := makePsbtReferencingMany([]domain.VtxoKey{
		{Txid: redeemTx1ID, VOut: 0},
		{Txid: redeemTx2ID, VOut: 1},
	})
	require.NoError(t, err)

	mockData := map[domain.VtxoKey]domain.Vtxo{
		{Txid: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", VOut: 0}: {
			VtxoKey:   domain.VtxoKey{Txid: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", VOut: 0},
			RoundTxid: "roundTxid",
			CreatedAt: time.Now().Add(-5 * time.Hour).Unix(),
		},
		{Txid: redeemTx1ID, VOut: 0}: {
			VtxoKey:   domain.VtxoKey{Txid: redeemTx1ID, VOut: 0},
			RedeemTx:  redeemTx1,
			CreatedAt: time.Now().Add(-4 * time.Hour).Unix(),
		},
		{Txid: redeemTx1ID, VOut: 1}: {
			VtxoKey:   domain.VtxoKey{Txid: redeemTx1ID, VOut: 1},
			RedeemTx:  redeemTx1,
			CreatedAt: time.Now().Add(-4 * time.Hour).Unix(),
		},

		{Txid: redeemTx2ID, VOut: 0}: {
			VtxoKey:   domain.VtxoKey{Txid: redeemTx2ID, VOut: 0},
			RedeemTx:  redeemTx2,
			CreatedAt: time.Now().Add(-3 * time.Hour).Unix(),
		},
		{Txid: redeemTx2ID, VOut: 1}: {
			VtxoKey:   domain.VtxoKey{Txid: redeemTx2ID, VOut: 1},
			RedeemTx:  redeemTx2,
			CreatedAt: time.Now().Add(-3 * time.Hour).Unix(),
		},

		{Txid: redeemTx3ID, VOut: 0}: {
			VtxoKey:   domain.VtxoKey{Txid: redeemTx3ID, VOut: 0},
			RedeemTx:  redeemTx3,
			CreatedAt: time.Now().Add(-1 * time.Hour).Unix(),
		},
	}

	vtxoRepo := &MockVtxoRepo{data: mockData}
	repoManager := &MockRepoManager{vtxoRepo: vtxoRepo}
	svc := indexerService{repoManager: repoManager}

	outpoint := Outpoint{
		Txid: redeemTx3ID,
		Vout: 0,
	}

	resp, err := svc.GetVtxoChain(ctx, outpoint, nil)
	require.NoError(t, err, "buildChain should succeed")

	redeemTx3Txs := resp.Transactions[redeemTx3ID]
	assert.Equal(t, len(redeemTx3Txs), 2)
	assert.Equal(t, redeemTx3Txs[0], redeemTx1ID)
	assert.Equal(t, redeemTx3Txs[1], redeemTx2ID)

	redeemTx2Txs := resp.Transactions[redeemTx2ID]
	assert.Equal(t, len(redeemTx2Txs), 1)
	assert.Equal(t, redeemTx2Txs[0], redeemTx1ID)

	redeemTx1Txs := resp.Transactions[redeemTx1ID]
	assert.Equal(t, len(redeemTx1Txs), 1)
	assert.Equal(t, redeemTx1Txs[0], "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

	leafTxTxs := resp.Transactions["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
	assert.Equal(t, len(leafTxTxs), 1)
	assert.Equal(t, leafTxTxs[0], "roundTxid")
}

type MockRepoManager struct {
	vtxoRepo *MockVtxoRepo
}

func (m *MockRepoManager) Events() domain.RoundEventRepository       { panic("not implemented") }
func (m *MockRepoManager) Rounds() domain.RoundRepository            { panic("not implemented") }
func (m *MockRepoManager) Vtxos() domain.VtxoRepository              { return m.vtxoRepo }
func (m *MockRepoManager) Notes() domain.NoteRepository              { panic("not implemented") }
func (m *MockRepoManager) Entities() domain.EntityRepository         { panic("not implemented") }
func (m *MockRepoManager) MarketHourRepo() domain.MarketHourRepo     { panic("not implemented") }
func (m *MockRepoManager) RegisterEventsHandler(func(*domain.Round)) { panic("not implemented") }
func (m *MockRepoManager) Close()                                    {}

type MockVtxoRepo struct {
	data map[domain.VtxoKey]domain.Vtxo
}

func (m *MockVtxoRepo) GetSpendableVtxosWithPubKey(ctx context.Context, pubkey string) ([]domain.Vtxo, error) {
	panic("not implemented")
}

func (m *MockVtxoRepo) AddVtxos(ctx context.Context, vtxos []domain.Vtxo) error {
	panic("not implemented")
}
func (m *MockVtxoRepo) SpendVtxos(ctx context.Context, vtxos []domain.VtxoKey, txid string) error {
	panic("not implemented")
}
func (m *MockVtxoRepo) RedeemVtxos(ctx context.Context, vtxos []domain.VtxoKey) error {
	panic("not implemented")
}
func (m *MockVtxoRepo) GetVtxos(ctx context.Context, vtxos []domain.VtxoKey) ([]domain.Vtxo, error) {
	var out []domain.Vtxo
	for _, k := range vtxos {
		if v, ok := m.data[k]; ok {
			out = append(out, v)
		}
	}
	return out, nil
}
func (m *MockVtxoRepo) GetVtxosForRound(ctx context.Context, txid string) ([]domain.Vtxo, error) {
	panic("not implemented")
}
func (m *MockVtxoRepo) SweepVtxos(ctx context.Context, vtxos []domain.VtxoKey) error {
	panic("not implemented")
}
func (m *MockVtxoRepo) GetAllNonRedeemedVtxos(ctx context.Context, pubkey string) ([]domain.Vtxo, []domain.Vtxo, error) {
	panic("not implemented")
}
func (m *MockVtxoRepo) GetAllSweepableVtxos(ctx context.Context) ([]domain.Vtxo, error) {
	panic("not implemented")
}
func (m *MockVtxoRepo) GetAll(ctx context.Context) ([]domain.Vtxo, error) { panic("not implemented") }
func (m *MockVtxoRepo) UpdateExpireAt(ctx context.Context, vtxos []domain.VtxoKey, expireAt int64) error {
	panic("not implemented")
}
func (m *MockVtxoRepo) Close() {}

func makePsbtReferencingMany(parents []domain.VtxoKey) (string, string, error) {
	tx := wire.NewMsgTx(wire.TxVersion)
	for _, p := range parents {
		parentHash, err := chainhash.NewHashFromStr(p.Txid)
		if err != nil {
			return "", "", err
		}
		txIn := wire.NewTxIn(wire.NewOutPoint(parentHash, p.VOut), nil, nil)
		tx.AddTxIn(txIn)
	}

	tx.AddTxOut(wire.NewTxOut(1000, []byte{}))

	p, err := psbt.NewFromUnsignedTx(tx)
	if err != nil {
		return "", "", err
	}

	ptxHex, err := p.B64Encode()
	if err != nil {
		return "", "", err
	}

	return ptxHex, tx.TxHash().String(), nil
}
