package db_test

import (
	"context"
	"encoding/hex"
	"math/rand"
	"os"
	"testing"

	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/internal/core/domain"
	badgerdb "github.com/ark-network/ark/internal/infrastructure/db/badger"
	sqlitedb "github.com/ark-network/ark/internal/infrastructure/db/sqlite"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	m.Run()
	_ = os.Remove("test.db")
}

type repos struct {
	vtxoRepo  domain.VtxoRepository
	roundRepo domain.RoundRepository
}

func getRepositories(t *testing.T) map[string]repos {
	badgerVtxoRepo, err := badgerdb.NewVtxoRepository("", nil)
	require.NoError(t, err)

	badgerRoundRepo, err := badgerdb.NewRoundRepository("", nil)
	require.NoError(t, err)

	db, err := sqlitedb.OpenDB("test.db")
	require.NoError(t, err)

	sqliteVtxoRepo, err := sqlitedb.NewVtxoRepository(db)
	require.NoError(t, err)

	sqliteRoundRepo, err := sqlitedb.NewRoundRepository(db)
	require.NoError(t, err)

	badger := repos{
		vtxoRepo:  badgerVtxoRepo,
		roundRepo: badgerRoundRepo,
	}

	sqlite := repos{
		vtxoRepo:  sqliteVtxoRepo,
		roundRepo: sqliteRoundRepo,
	}

	return map[string]repos{
		"badger": badger,
		"sqlite": sqlite,
	}
}

func TestRoundRepository(t *testing.T) {
	dbs := getRepositories(t)

	for name, repos := range dbs {
		repo := repos.roundRepo
		t.Run(name, func(t *testing.T) {

			t.Run("AddOrUpdateRound", func(t *testing.T) {
				roundId := randomString(32)
				txid := randomString(32)
				round := domain.Round{
					Id:                roundId,
					StartingTimestamp: 123,
					EndingTimestamp:   123,
					Stage: domain.Stage{
						Code:   domain.FinalizationStage,
						Ended:  true,
						Failed: false,
					},
					Txid:       txid,
					UnsignedTx: "unsignedTx",
					CongestionTree: tree.CongestionTree{
						[]tree.Node{
							{
								Txid:       "txid",
								Tx:         "tx",
								ParentTxid: "parentTxid",
								Leaf:       false,
							},
						},
						[]tree.Node{
							{
								Txid:       "txid",
								Tx:         "tx",
								ParentTxid: "parentTxid",
								Leaf:       true,
							},
							{
								Txid:       "txid",
								Tx:         "tx",
								ParentTxid: "parentTxid",
								Leaf:       true,
							},
						},
					},
					ForfeitTxs:       []string{"tx1", "tx2"},
					Connectors:       []string{"connector1", "connector2"},
					ConnectorAddress: "connectorAddress",
					DustAmount:       100,
					Version:          1,
					Swept:            false,
					Payments: map[string]domain.Payment{
						"1": {
							Id: "1",
							Inputs: []domain.Vtxo{
								{VtxoKey: domain.VtxoKey{Txid: "txid", VOut: 0}},
								{VtxoKey: domain.VtxoKey{Txid: "txid2", VOut: 1}},
							},
							Receivers: []domain.Receiver{{Pubkey: "pubkey", Amount: 100}},
						},
					},
				}
				err := repos.vtxoRepo.AddVtxos(context.Background(), round.Payments["1"].Inputs)
				require.NoError(t, err)

				err = repo.AddOrUpdateRound(context.Background(), round)
				require.NoError(t, err)

				roundFromDB, err := repo.GetRoundWithId(context.Background(), roundId)
				require.NoError(t, err)

				require.Equal(t, roundId, roundFromDB.Id)
				require.Equal(t, int64(123), roundFromDB.StartingTimestamp)
				require.Equal(t, int64(123), roundFromDB.EndingTimestamp)
				require.Equal(t, domain.FinalizationStage, roundFromDB.Stage.Code)
				require.True(t, roundFromDB.Stage.Ended)
				require.False(t, roundFromDB.Stage.Failed)
				require.Equal(t, txid, roundFromDB.Txid)
				require.Equal(t, "unsignedTx", roundFromDB.UnsignedTx)
				require.Len(t, roundFromDB.CongestionTree, 2)
				require.Len(t, roundFromDB.ForfeitTxs, 2)
				require.Len(t, roundFromDB.Connectors, 2)
				require.Equal(t, "connectorAddress", roundFromDB.ConnectorAddress)
				require.Equal(t, uint64(100), roundFromDB.DustAmount)
				require.Equal(t, uint(1), roundFromDB.Version)
				require.False(t, roundFromDB.Swept)
				require.Len(t, roundFromDB.Payments, 1)
				require.Len(t, roundFromDB.Payments["1"].Inputs, 2)
				require.Len(t, roundFromDB.Payments["1"].Receivers, 1)

				round.Payments["2"] = domain.Payment{
					Id: "2",
					Inputs: []domain.Vtxo{
						{VtxoKey: domain.VtxoKey{Txid: "txid3", VOut: 0}},
						{VtxoKey: domain.VtxoKey{Txid: "txid4", VOut: 1}},
					},
					Receivers: []domain.Receiver{{Pubkey: "pubkey2333", Amount: 200}},
				}
				round.Stage.Code = domain.RegistrationStage
				err = repos.vtxoRepo.AddVtxos(context.Background(), round.Payments["2"].Inputs)
				require.NoError(t, err)

				err = repo.AddOrUpdateRound(context.Background(), round)
				require.NoError(t, err)

				roundFromDB, err = repo.GetRoundWithId(context.Background(), roundId)
				require.NoError(t, err)

				require.Len(t, roundFromDB.Payments, 2)
				require.Len(t, roundFromDB.Payments["2"].Inputs, 2)
				require.Len(t, roundFromDB.Payments["2"].Receivers, 1)
				require.Equal(t, domain.RegistrationStage, roundFromDB.Stage.Code)
			})

			t.Run("GetCurrentRound", func(t *testing.T) {
				round := domain.NewRound(800)

				err := repo.AddOrUpdateRound(context.Background(), *round)
				require.NoError(t, err)

				current, err := repo.GetCurrentRound(context.Background())
				require.NoError(t, err)

				require.Equal(t, round.Id, current.Id)
			})

			t.Run("GetRoundWithTxid", func(t *testing.T) {
				roundId := randomString(32)
				txid := randomString(32)
				round := domain.Round{
					Id:                roundId,
					StartingTimestamp: 123,
					EndingTimestamp:   123,
					Stage: domain.Stage{
						Code:   domain.FinalizationStage,
						Ended:  false,
						Failed: false,
					},
					Txid:       txid,
					UnsignedTx: "unsignedTx",
					CongestionTree: tree.CongestionTree{
						[]tree.Node{
							{
								Txid:       "txid",
								Tx:         "tx",
								ParentTxid: "parentTxid",
								Leaf:       false,
							},
						},
						[]tree.Node{
							{
								Txid:       "txid",
								Tx:         "tx",
								ParentTxid: "parentTxid",
								Leaf:       true,
							},
							{
								Txid:       "txid",
								Tx:         "tx",
								ParentTxid: "parentTxid",
								Leaf:       true,
							},
						},
					},
					ForfeitTxs:       []string{"tx1", "tx2"},
					Connectors:       []string{"connector1", "connector2"},
					ConnectorAddress: "connectorAddress",
					DustAmount:       100,
					Version:          1,
					Swept:            false,
				}

				err := repo.AddOrUpdateRound(context.Background(), round)
				require.NoError(t, err)

				byid, err := repo.GetRoundWithTxid(context.Background(), txid)
				require.NoError(t, err)

				require.Equal(t, roundId, byid.Id)
				require.Equal(t, txid, byid.Txid)
			})

			t.Run("GetRoundWithId", func(t *testing.T) {
				roundId := randomString(32)
				txid := randomString(32)
				round := domain.Round{
					Id:                roundId,
					StartingTimestamp: 123,
					EndingTimestamp:   123,
					Stage: domain.Stage{
						Code:   domain.FinalizationStage,
						Ended:  false,
						Failed: false,
					},
					Txid:       txid,
					UnsignedTx: "unsignedTx",
					CongestionTree: tree.CongestionTree{
						[]tree.Node{
							{
								Txid:       "txid",
								Tx:         "tx",
								ParentTxid: "parentTxid",
								Leaf:       false,
							},
						},
						[]tree.Node{
							{
								Txid:       "txid",
								Tx:         "tx",
								ParentTxid: "parentTxid",
								Leaf:       true,
							},
							{
								Txid:       "txid",
								Tx:         "tx",
								ParentTxid: "parentTxid",
								Leaf:       true,
							},
						},
					},
					ForfeitTxs:       []string{"tx1", "tx2"},
					Connectors:       []string{"connector1", "connector2"},
					ConnectorAddress: "connectorAddress",
					DustAmount:       100,
					Version:          1,
					Swept:            false,
				}

				err := repo.AddOrUpdateRound(context.Background(), round)
				require.NoError(t, err)

				byid, err := repo.GetRoundWithId(context.Background(), roundId)
				require.NoError(t, err)

				require.Equal(t, roundId, byid.Id)
			})

			t.Run("GetSweepableRounds", func(t *testing.T) {
				roundId := randomString(32)
				txid := randomString(32)
				round := domain.Round{
					Id:                roundId,
					StartingTimestamp: 123,
					EndingTimestamp:   123,
					Stage: domain.Stage{
						Code:   domain.FinalizationStage,
						Ended:  true,
						Failed: false,
					},
					Txid:       txid,
					UnsignedTx: "unsignedTx",
					CongestionTree: tree.CongestionTree{
						[]tree.Node{
							{
								Txid:       "txid",
								Tx:         "tx",
								ParentTxid: "parentTxid",
								Leaf:       false,
							},
						},
						[]tree.Node{
							{
								Txid:       "txid",
								Tx:         "tx",
								ParentTxid: "parentTxid",
								Leaf:       true,
							},
							{
								Txid:       "txid",
								Tx:         "tx",
								ParentTxid: "parentTxid",
								Leaf:       true,
							},
						},
					},
					ForfeitTxs:       []string{"tx1", "tx2"},
					Connectors:       []string{"connector1", "connector2"},
					ConnectorAddress: "connectorAddress",
					DustAmount:       100,
					Version:          1,
					Swept:            false,
				}

				err := repo.AddOrUpdateRound(context.Background(), round)
				require.NoError(t, err)

				byid, err := repo.GetRoundWithId(context.Background(), roundId)
				require.NoError(t, err)

				require.Equal(t, roundId, byid.Id)

				sweepable, err := repo.GetSweepableRounds(context.Background())
				require.NoError(t, err)

				require.GreaterOrEqual(t, len(sweepable), 1)
			})

			t.Run("GetSweptRounds", func(t *testing.T) {
				roundId := randomString(32)
				txid := randomString(32)
				round := domain.Round{
					Id:                roundId,
					StartingTimestamp: 123,
					EndingTimestamp:   123,
					Stage: domain.Stage{
						Code:   domain.FinalizationStage,
						Ended:  true,
						Failed: false,
					},
					Txid:       txid,
					UnsignedTx: "unsignedTx",
					CongestionTree: tree.CongestionTree{
						[]tree.Node{
							{
								Txid:       "txid",
								Tx:         "tx",
								ParentTxid: "parentTxid",
								Leaf:       false,
							},
						},
						[]tree.Node{
							{
								Txid:       "txid",
								Tx:         "tx",
								ParentTxid: "parentTxid",
								Leaf:       true,
							},
							{
								Txid:       "txid",
								Tx:         "tx",
								ParentTxid: "parentTxid",
								Leaf:       true,
							},
						},
					},
					ForfeitTxs:       []string{"tx1", "tx2"},
					Connectors:       []string{"connector1", "connector2"},
					ConnectorAddress: "connectorAddress",
					DustAmount:       100,
					Version:          1,
					Swept:            true,
				}

				err := repo.AddOrUpdateRound(context.Background(), round)
				require.NoError(t, err)

				byid, err := repo.GetRoundWithId(context.Background(), roundId)
				require.NoError(t, err)

				require.Equal(t, roundId, byid.Id)

				swept, err := repo.GetSweptRounds(context.Background())
				require.NoError(t, err)

				require.GreaterOrEqual(t, len(swept), 1)
			})
		})
	}
}

func TestVtxoRepository(t *testing.T) {
	dbs := getRepositories(t)

	for name, repos := range dbs {
		repo := repos.vtxoRepo
		t.Run(name, func(t *testing.T) {

			t.Run("AddVtxos", func(t *testing.T) {
				txid := randomString(32)
				vtxos := []domain.Vtxo{
					{
						VtxoKey: domain.VtxoKey{
							Txid: txid,
							VOut: 0,
						},
						Receiver: domain.Receiver{
							Pubkey: "pubkey",
							Amount: 100,
						},
						PoolTx:   "pooltx",
						SpentBy:  "spentBy",
						Spent:    false,
						Redeemed: false,
						Swept:    false,
						ExpireAt: 902223,
					},
				}

				err := repo.AddVtxos(context.Background(), vtxos)
				require.NoError(t, err)

				vtxos, err = repo.GetVtxos(context.Background(), []domain.VtxoKey{{
					Txid: txid,
					VOut: 0,
				}})
				require.NoError(t, err)

				require.Len(t, vtxos, 1)
			})

			t.Run("SpendVtxos", func(t *testing.T) {
				txid := randomString(32)
				err := repo.AddVtxos(context.Background(), []domain.Vtxo{{
					VtxoKey: domain.VtxoKey{
						Txid: txid,
						VOut: 0,
					},
					Receiver: domain.Receiver{
						Pubkey: "pubkey",
						Amount: 100,
					},
					PoolTx:   "pooltx",
					SpentBy:  "spentBy",
					Spent:    false,
					Redeemed: false,
					Swept:    false,
					ExpireAt: 902223,
				}})
				require.NoError(t, err)

				err = repo.SpendVtxos(context.Background(), []domain.VtxoKey{{
					Txid: txid,
					VOut: 0,
				}}, "txid")
				require.NoError(t, err)

				vtxos, err := repo.GetVtxos(context.Background(), []domain.VtxoKey{{
					Txid: txid,
					VOut: 0,
				}})
				require.NoError(t, err)

				require.True(t, vtxos[0].Spent)
				require.Equal(t, "txid", vtxos[0].SpentBy)
			})

			t.Run("RedeemVtxos", func(t *testing.T) {
				txid := randomString(32)
				err := repo.AddVtxos(context.Background(), []domain.Vtxo{{
					VtxoKey: domain.VtxoKey{
						Txid: txid,
						VOut: 0,
					},
					Receiver: domain.Receiver{
						Pubkey: "pubkey",
						Amount: 100,
					},
					PoolTx:   "pooltx",
					SpentBy:  "spentBy",
					Spent:    false,
					Redeemed: false,
					Swept:    false,
					ExpireAt: 902223,
				}})
				require.NoError(t, err)

				err = repo.RedeemVtxos(context.Background(), []domain.VtxoKey{{
					Txid: txid,
					VOut: 0,
				}})
				require.NoError(t, err)

				vtxos, err := repo.GetVtxos(context.Background(), []domain.VtxoKey{{
					Txid: txid,
					VOut: 0,
				}})
				require.NoError(t, err)

				require.True(t, vtxos[0].Redeemed)
			})

			t.Run("SweepVtxos", func(t *testing.T) {
				txid := randomString(32)
				err := repo.AddVtxos(context.Background(), []domain.Vtxo{{
					VtxoKey: domain.VtxoKey{
						Txid: txid,
						VOut: 0,
					},
					Receiver: domain.Receiver{
						Pubkey: "pubkey",
						Amount: 100,
					},
					PoolTx:   "pooltx",
					SpentBy:  "spentBy",
					Spent:    false,
					Redeemed: false,
					Swept:    false,
					ExpireAt: 902223,
				}})
				require.NoError(t, err)

				err = repo.SweepVtxos(context.Background(), []domain.VtxoKey{{
					Txid: txid,
					VOut: 0,
				}})
				require.NoError(t, err)

				vtxos, err := repo.GetVtxos(context.Background(), []domain.VtxoKey{{
					Txid: txid,
					VOut: 0,
				}})
				require.NoError(t, err)

				require.True(t, vtxos[0].Swept)
			})

			t.Run("GetAllVtxos", func(t *testing.T) {
				txid := randomString(32)
				err := repo.AddVtxos(context.Background(), []domain.Vtxo{{
					VtxoKey: domain.VtxoKey{
						Txid: txid,
						VOut: 0,
					},
					Receiver: domain.Receiver{
						Pubkey: "pubkey",
						Amount: 100,
					},
					PoolTx:   "pooltx",
					SpentBy:  "spentBy",
					Spent:    false,
					Redeemed: false,
					Swept:    false,
					ExpireAt: 902223,
				}})
				require.NoError(t, err)

				unspentsVtxos, spentVtxos, err := repo.GetAllVtxos(context.Background(), "")
				require.NoError(t, err)

				totalVtxos := append(unspentsVtxos, spentVtxos...)
				require.GreaterOrEqual(t, len(totalVtxos), 1)
			})

			t.Run("GetAllSweepableVtxos", func(t *testing.T) {
				txid := randomString(10)
				err := repo.AddVtxos(context.Background(), []domain.Vtxo{{
					VtxoKey: domain.VtxoKey{
						Txid: txid,
						VOut: 0,
					},
					Receiver: domain.Receiver{
						Pubkey: "pubkey",
						Amount: 100,
					},
					PoolTx:   "pooltx",
					SpentBy:  "spentBy",
					Spent:    false,
					Redeemed: false,
					Swept:    false,
					ExpireAt: 902223,
				}})
				require.NoError(t, err)

				vtxos, err := repo.GetAllSweepableVtxos(context.Background())
				require.NoError(t, err)
				require.GreaterOrEqual(t, len(vtxos), 1)
			})

			t.Run("UpdateExpireAt", func(t *testing.T) {
				txid := randomString(32)
				err := repo.AddVtxos(context.Background(), []domain.Vtxo{{
					VtxoKey: domain.VtxoKey{
						Txid: txid,
						VOut: 0,
					},
					Receiver: domain.Receiver{
						Pubkey: "pubkey",
						Amount: 100,
					},
					PoolTx:   "pooltx",
					SpentBy:  "spentBy",
					Spent:    false,
					Redeemed: false,
					Swept:    false,
					ExpireAt: 902223,
				}})
				require.NoError(t, err)

				err = repo.UpdateExpireAt(context.Background(), []domain.VtxoKey{{
					Txid: txid,
					VOut: 0,
				}}, 902224)
				require.NoError(t, err)

				vtxos, err := repo.GetVtxos(context.Background(), []domain.VtxoKey{{
					Txid: txid,
					VOut: 0,
				}})
				require.NoError(t, err)

				require.Equal(t, int64(902224), vtxos[0].ExpireAt)
			})
		})
	}
}

func randomString(len int) string {
	buf := make([]byte, len)
	// nolint
	rand.Read(buf)
	return hex.EncodeToString(buf)
}
