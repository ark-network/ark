package db_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/ark-network/ark/server/internal/core/ports"
	"github.com/ark-network/ark/server/internal/infrastructure/db"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	emptyPtx = "cHNldP8BAgQCAAAAAQQBAAEFAQABBgEDAfsEAgAAAAA="
	emptyTx  = "0200000000000000000000"
	pubkey   = "25a43cecfa0e1b1a4f72d64ad15f4cfa7a84d0723e8511c969aa543638ea9967"
	pubkey2  = "33ffb3dee353b1a9ebe4ced64b946238d0a4ac364f275d771da6ad2445d07ae0"
)

var (
	vtxoTree = [][]tree.Node{
		{
			{
				Txid:       randomString(32),
				Tx:         emptyPtx,
				ParentTxid: randomString(32),
			},
		},
		{
			{
				Txid:       randomString(32),
				Tx:         emptyPtx,
				ParentTxid: randomString(32),
			},
			{
				Txid:       randomString(32),
				Tx:         emptyPtx,
				ParentTxid: randomString(32),
			},
		},
		{
			{
				Txid:       randomString(32),
				Tx:         emptyPtx,
				ParentTxid: randomString(32),
			},
			{
				Txid:       randomString(32),
				Tx:         emptyPtx,
				ParentTxid: randomString(32),
			},
			{
				Txid:       randomString(32),
				Tx:         emptyPtx,
				ParentTxid: randomString(32),
			},
			{
				Txid:       randomString(32),
				Tx:         emptyPtx,
				ParentTxid: randomString(32),
			},
		},
	}
	connectorsTree = [][]tree.Node{
		{
			{
				Txid:       randomString(32),
				Tx:         emptyPtx,
				ParentTxid: randomString(32),
			},
		},
		{
			{
				Txid:       randomString(32),
				Tx:         emptyPtx,
				ParentTxid: randomString(32),
			},
			{
				Txid:       randomString(32),
				Tx:         emptyPtx,
				ParentTxid: randomString(32),
			},
		},
	}
)

func TestMain(m *testing.M) {
	m.Run()
	_ = os.Remove("test.db")
}

func TestService(t *testing.T) {
	dbDir := t.TempDir()
	tests := []struct {
		name   string
		config db.ServiceConfig
	}{
		{
			name: "repo_manager_with_badger_stores",
			config: db.ServiceConfig{
				EventStoreType:   "badger",
				DataStoreType:    "badger",
				EventStoreConfig: []interface{}{"", nil},
				DataStoreConfig:  []interface{}{"", nil},
			},
		},
		{
			name: "repo_manager_with_sqlite_stores",
			config: db.ServiceConfig{
				EventStoreType:   "badger",
				DataStoreType:    "sqlite",
				EventStoreConfig: []interface{}{"", nil},
				DataStoreConfig:  []interface{}{dbDir},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, err := db.NewService(tt.config)
			require.NoError(t, err)
			defer svc.Close()

			testRoundEventRepository(t, svc)
			testRoundRepository(t, svc)
			testVtxoRepository(t, svc)
			testNoteRepository(t, svc)
			testEntityRepository(t, svc)
			testMarketHourRepository(t, svc)
		})
	}
}

func testRoundEventRepository(t *testing.T, svc ports.RepoManager) {
	t.Run("test_event_repository", func(t *testing.T) {
		fixtures := []struct {
			roundId string
			events  []domain.RoundEvent
			handler func(*domain.Round)
		}{
			{
				roundId: "42dd81f7-cadd-482c-bf69-8e9209aae9f3",
				events: []domain.RoundEvent{
					domain.RoundStarted{
						Id:        "42dd81f7-cadd-482c-bf69-8e9209aae9f3",
						Timestamp: 1701190270,
					},
				},
				handler: func(round *domain.Round) {
					require.NotNil(t, round)
					require.Len(t, round.Events(), 1)
					require.True(t, round.IsStarted())
					require.False(t, round.IsFailed())
					require.False(t, round.IsEnded())
				},
			},
			{
				roundId: "1ea610ff-bf3e-4068-9bfd-b6c3f553467e",
				events: []domain.RoundEvent{
					domain.RoundStarted{
						Id:        "1ea610ff-bf3e-4068-9bfd-b6c3f553467e",
						Timestamp: 1701190270,
					},
					domain.RoundFinalizationStarted{
						Id:         "1ea610ff-bf3e-4068-9bfd-b6c3f553467e",
						VtxoTree:   vtxoTree,
						Connectors: connectorsTree,
						RoundTx:    emptyTx,
					},
				},
				handler: func(round *domain.Round) {
					require.NotNil(t, round)
					require.Len(t, round.Events(), 2)
					require.Len(t, round.VtxoTree, 3)
					require.Equal(t, round.VtxoTree.NumberOfNodes(), 7)
					require.Len(t, round.Connectors, 2)
				},
			},
			{
				roundId: "7578231e-428d-45ae-aaa4-e62c77ad5cec",
				events: []domain.RoundEvent{
					domain.RoundStarted{
						Id:        "7578231e-428d-45ae-aaa4-e62c77ad5cec",
						Timestamp: 1701190270,
					},
					domain.RoundFinalizationStarted{
						Id:         "7578231e-428d-45ae-aaa4-e62c77ad5cec",
						VtxoTree:   vtxoTree,
						Connectors: connectorsTree,
						RoundTx:    emptyTx,
					},
					domain.RoundFinalized{
						Id:         "7578231e-428d-45ae-aaa4-e62c77ad5cec",
						Txid:       randomString(32),
						ForfeitTxs: []string{emptyPtx, emptyPtx, emptyPtx, emptyPtx},
						Timestamp:  1701190300,
					},
				},
				handler: func(round *domain.Round) {
					require.NotNil(t, round)
					require.Len(t, round.Events(), 3)
					require.False(t, round.IsStarted())
					require.False(t, round.IsFailed())
					require.True(t, round.IsEnded())
					require.NotEmpty(t, round.Txid)
				},
			},
		}
		ctx := context.Background()

		for _, f := range fixtures {
			svc.RegisterEventsHandler(f.handler)

			round, err := svc.Events().Save(ctx, f.roundId, f.events...)
			require.NoError(t, err)
			require.NotNil(t, round)

			round, err = svc.Events().Load(ctx, f.roundId)
			require.NoError(t, err)
			require.NotNil(t, round)
			require.Equal(t, f.roundId, round.Id)
			require.Len(t, round.Events(), len(f.events))
		}
	})
}

func testRoundRepository(t *testing.T, svc ports.RepoManager) {
	t.Run("test_round_repository", func(t *testing.T) {
		ctx := context.Background()
		now := time.Now()

		roundId := uuid.New().String()

		round, err := svc.Rounds().GetRoundWithId(ctx, roundId)
		require.Error(t, err)
		require.Nil(t, round)

		events := []domain.RoundEvent{
			domain.RoundStarted{
				Id:        roundId,
				Timestamp: now.Unix(),
			},
		}
		round = domain.NewRoundFromEvents(events)
		err = svc.Rounds().AddOrUpdateRound(ctx, *round)
		require.NoError(t, err)

		roundById, err := svc.Rounds().GetRoundWithId(ctx, roundId)
		require.NoError(t, err)
		require.NotNil(t, roundById)
		require.Condition(t, roundsMatch(*round, *roundById))

		newEvents := []domain.RoundEvent{
			domain.TxRequestsRegistered{
				Id: roundId,
				TxRequests: []domain.TxRequest{
					{
						Id: uuid.New().String(),
						Inputs: []domain.Vtxo{
							{
								VtxoKey: domain.VtxoKey{
									Txid: randomString(32),
									VOut: 0,
								},
								RoundTxid: randomString(32),
								ExpireAt:  7980322,
								PubKey:    randomString(32),
								Amount:    300,
							},
						},
						Receivers: []domain.Receiver{{
							PubKey: randomString(32),
							Amount: 300,
						}},
					},
					{
						Id: uuid.New().String(),
						Inputs: []domain.Vtxo{

							{
								VtxoKey: domain.VtxoKey{
									Txid: randomString(32),
									VOut: 0,
								},
								RoundTxid: randomString(32),
								ExpireAt:  7980322,
								PubKey:    randomString(32),
								Amount:    600,
							},
						},
						Receivers: []domain.Receiver{
							{
								PubKey: randomString(32),
								Amount: 400,
							},
							{
								PubKey: randomString(32),
								Amount: 200,
							},
						},
					},
				},
			},
			domain.RoundFinalizationStarted{
				Id:         roundId,
				VtxoTree:   vtxoTree,
				Connectors: connectorsTree,
				RoundTx:    emptyTx,
			},
		}
		events = append(events, newEvents...)
		updatedRound := domain.NewRoundFromEvents(events)
		for _, request := range updatedRound.TxRequests {
			err = svc.Vtxos().AddVtxos(ctx, request.Inputs)
			require.NoError(t, err)
		}

		err = svc.Rounds().AddOrUpdateRound(ctx, *updatedRound)
		require.NoError(t, err)

		roundById, err = svc.Rounds().GetRoundWithId(ctx, updatedRound.Id)
		require.NoError(t, err)
		require.NotNil(t, roundById)
		require.Condition(t, roundsMatch(*updatedRound, *roundById))

		txid := randomString(32)
		newEvents = []domain.RoundEvent{
			domain.RoundFinalized{
				Id:         roundId,
				Txid:       txid,
				ForfeitTxs: []string{emptyPtx, emptyPtx, emptyPtx, emptyPtx},
				Timestamp:  now.Add(60 * time.Second).Unix(),
			},
		}
		events = append(events, newEvents...)
		finalizedRound := domain.NewRoundFromEvents(events)

		err = svc.Rounds().AddOrUpdateRound(ctx, *finalizedRound)
		require.NoError(t, err)

		roundById, err = svc.Rounds().GetRoundWithId(ctx, roundId)
		require.NoError(t, err)
		require.NotNil(t, roundById)
		require.Condition(t, roundsMatch(*finalizedRound, *roundById))

		resultTree, err := svc.Rounds().GetVtxoTreeWithTxid(ctx, txid)
		require.NoError(t, err)
		require.NotNil(t, resultTree)
		require.Equal(t, finalizedRound.VtxoTree, resultTree)

		roundByTxid, err := svc.Rounds().GetRoundWithTxid(ctx, txid)
		require.NoError(t, err)
		require.NotNil(t, roundByTxid)
		require.Condition(t, roundsMatch(*finalizedRound, *roundByTxid))
	})
}

func testVtxoRepository(t *testing.T, svc ports.RepoManager) {
	t.Run("test_vtxo_repository", func(t *testing.T) {
		ctx := context.Background()

		userVtxos := []domain.Vtxo{
			{
				VtxoKey: domain.VtxoKey{
					Txid: randomString(32),
					VOut: 0,
				},
				PubKey: pubkey,
				Amount: 1000,
			},
			{
				VtxoKey: domain.VtxoKey{
					Txid: randomString(32),
					VOut: 1,
				},
				PubKey: pubkey,
				Amount: 2000,
			},
		}
		newVtxos := append(userVtxos, domain.Vtxo{
			VtxoKey: domain.VtxoKey{
				Txid: randomString(32),
				VOut: 1,
			},
			PubKey: pubkey2,
			Amount: 2000,
		})

		vtxoKeys := make([]domain.VtxoKey, 0, len(userVtxos))
		for _, v := range userVtxos {
			vtxoKeys = append(vtxoKeys, v.VtxoKey)
		}

		vtxos, err := svc.Vtxos().GetVtxos(ctx, vtxoKeys)
		require.Error(t, err)
		require.Empty(t, vtxos)

		spendableVtxos, spentVtxos, err := svc.Vtxos().GetAllVtxos(ctx, pubkey)
		require.NoError(t, err)
		require.Empty(t, spendableVtxos)
		require.Empty(t, spentVtxos)

		spendableVtxos, spentVtxos, err = svc.Vtxos().GetAllVtxos(ctx, "")
		require.NoError(t, err)

		numberOfVtxos := len(spendableVtxos) + len(spentVtxos)

		err = svc.Vtxos().AddVtxos(ctx, newVtxos)
		require.NoError(t, err)

		vtxos, err = svc.Vtxos().GetVtxos(ctx, vtxoKeys)
		require.NoError(t, err)
		require.Exactly(t, userVtxos, vtxos)

		spendableVtxos, spentVtxos, err = svc.Vtxos().GetAllVtxos(ctx, pubkey)
		require.NoError(t, err)

		sortedVtxos := sortVtxos(userVtxos)
		sort.Sort(sortedVtxos)

		sortedSpendableVtxos := sortVtxos(spendableVtxos)
		sort.Sort(sortedSpendableVtxos)

		require.Exactly(t, sortedSpendableVtxos, sortedVtxos)
		require.Empty(t, spentVtxos)

		spendableVtxos, spentVtxos, err = svc.Vtxos().GetAllVtxos(ctx, "")
		require.NoError(t, err)
		require.Len(t, append(spendableVtxos, spentVtxos...), numberOfVtxos+len(newVtxos))

		err = svc.Vtxos().SpendVtxos(ctx, vtxoKeys[:1], randomString(32))
		require.NoError(t, err)

		spentVtxos, err = svc.Vtxos().GetVtxos(ctx, vtxoKeys[:1])
		require.NoError(t, err)
		require.Len(t, spentVtxos, len(vtxoKeys[:1]))
		for _, v := range spentVtxos {
			require.True(t, v.Spent)
		}

		spendableVtxos, spentVtxos, err = svc.Vtxos().GetAllVtxos(ctx, pubkey)
		require.NoError(t, err)
		require.Exactly(t, vtxos[1:], spendableVtxos)
		require.Len(t, spentVtxos, len(vtxoKeys[:1]))
	})
}

func testNoteRepository(t *testing.T, svc ports.RepoManager) {
	t.Run("test_note_repository", func(t *testing.T) {
		ctx := context.Background()

		err := svc.Notes().Add(ctx, 1)
		require.NoError(t, err)

		err = svc.Notes().Add(ctx, 1099200322)
		require.NoError(t, err)

		contains, err := svc.Notes().Contains(ctx, 1)
		require.NoError(t, err)
		require.True(t, contains)

		contains, err = svc.Notes().Contains(ctx, 1099200322)
		require.NoError(t, err)
		require.True(t, contains)

		contains, err = svc.Notes().Contains(ctx, 456)
		require.NoError(t, err)
		require.False(t, contains)

		err = svc.Notes().Add(ctx, 1)
		require.Error(t, err)
	})
}

func testEntityRepository(t *testing.T, svc ports.RepoManager) {
	t.Run("test_entity_repository", func(t *testing.T) {
		ctx := context.Background()

		vtxoKey := domain.VtxoKey{
			Txid: randomString(32),
			VOut: 0,
		}

		entity := domain.Entity{
			NostrRecipient: "test",
		}

		// add
		err := svc.Entities().Add(ctx, entity, []domain.VtxoKey{vtxoKey})
		require.NoError(t, err)

		gotEntities, err := svc.Entities().Get(ctx, vtxoKey)
		require.NoError(t, err)
		require.NotNil(t, gotEntities)
		require.Equal(t, entity, gotEntities[0])

		// add another entity
		entity2 := domain.Entity{
			NostrRecipient: "test2",
		}

		err = svc.Entities().Add(ctx, entity2, []domain.VtxoKey{vtxoKey})
		require.NoError(t, err)

		// if nostrkey is the same, it should not be added
		err = svc.Entities().Add(ctx, entity2, []domain.VtxoKey{vtxoKey})
		require.NoError(t, err)

		gotEntities, err = svc.Entities().Get(ctx, vtxoKey)
		require.NoError(t, err)
		require.NotNil(t, gotEntities)
		require.Contains(t, gotEntities, entity)
		require.Contains(t, gotEntities, entity2)
		require.Len(t, gotEntities, 2)

		// delete
		err = svc.Entities().Delete(ctx, []domain.VtxoKey{vtxoKey})
		require.NoError(t, err)

		gotEntities, err = svc.Entities().Get(ctx, vtxoKey)
		require.Error(t, err)
		require.Nil(t, gotEntities)
	})
}

func testMarketHourRepository(t *testing.T, svc ports.RepoManager) {
	t.Run("test_market_hour_repository", func(t *testing.T) {
		ctx := context.Background()
		repo := svc.MarketHourRepo()
		defer repo.Close()

		marketHour, err := repo.Get(ctx)
		require.NoError(t, err)
		require.Nil(t, marketHour)

		now := time.Now().Truncate(time.Second)
		expected := domain.MarketHour{
			StartTime:     now,
			Period:        time.Duration(3) * time.Hour,
			RoundInterval: time.Duration(20) * time.Second,
			UpdatedAt:     now,
		}

		err = repo.Upsert(ctx, expected)
		require.NoError(t, err)

		got, err := repo.Get(ctx)
		require.NoError(t, err)
		require.NotNil(t, got)
		assertMarketHourEqual(t, expected, *got)

		expected.Period = time.Duration(4) * time.Hour
		expected.RoundInterval = time.Duration(40) * time.Second
		expected.UpdatedAt = now.Add(100 * time.Second)

		err = repo.Upsert(ctx, expected)
		require.NoError(t, err)

		got, err = repo.Get(ctx)
		require.NoError(t, err)
		require.NotNil(t, got)
		assertMarketHourEqual(t, expected, *got)
	})
}

func assertMarketHourEqual(t *testing.T, expected, actual domain.MarketHour) {
	assert.True(t, expected.StartTime.Equal(actual.StartTime), "StartTime not equal")
	assert.Equal(t, expected.Period, actual.Period, "Period not equal")
	assert.Equal(t, expected.RoundInterval, actual.RoundInterval, "RoundInterval not equal")
	assert.True(t, expected.UpdatedAt.Equal(actual.UpdatedAt), "UpdatedAt not equal")
	assert.True(t, expected.EndTime.Equal(actual.EndTime), "EndTime not equal")
}

func roundsMatch(expected, got domain.Round) assert.Comparison {
	return func() bool {
		if expected.Id != got.Id {
			return false
		}
		if expected.StartingTimestamp != got.StartingTimestamp {
			return false
		}
		if expected.EndingTimestamp != got.EndingTimestamp {
			return false
		}
		if expected.Stage != got.Stage {
			return false
		}

		for k, v := range expected.TxRequests {
			gotValue, ok := got.TxRequests[k]
			if !ok {
				return false
			}

			expectedVtxos := sortVtxos(v.Inputs)
			gotVtxos := sortVtxos(gotValue.Inputs)

			sort.Sort(expectedVtxos)
			sort.Sort(gotVtxos)

			expectedReceivers := sortReceivers(v.Receivers)
			gotReceivers := sortReceivers(gotValue.Receivers)

			sort.Sort(expectedReceivers)
			sort.Sort(gotReceivers)

			if !reflect.DeepEqual(expectedReceivers, gotReceivers) {
				return false
			}
			if !reflect.DeepEqual(expectedVtxos, gotVtxos) {
				return false
			}
		}

		if expected.Txid != got.Txid {
			return false
		}
		if expected.UnsignedTx != got.UnsignedTx {
			return false
		}

		if len(expected.ForfeitTxs) > 0 {
			expectedForfeits := sortStrings(expected.ForfeitTxs)
			gotForfeits := sortStrings(got.ForfeitTxs)

			sort.Sort(expectedForfeits)
			sort.Sort(gotForfeits)

			if !reflect.DeepEqual(expectedForfeits, gotForfeits) {
				return false
			}
		}

		if !reflect.DeepEqual(expected.VtxoTree, got.VtxoTree) {
			return false
		}

		if len(expected.Connectors) > 0 {
			if !reflect.DeepEqual(expected.Connectors, got.Connectors) {
				return false
			}
		}
		return expected.Version == got.Version
	}
}

func randomString(len int) string {
	buf := make([]byte, len)
	// nolint
	rand.Read(buf)
	return hex.EncodeToString(buf)
}

type sortVtxos []domain.Vtxo

func (a sortVtxos) Len() int           { return len(a) }
func (a sortVtxos) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a sortVtxos) Less(i, j int) bool { return a[i].Txid < a[j].Txid }

type sortReceivers []domain.Receiver

func (a sortReceivers) Len() int           { return len(a) }
func (a sortReceivers) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a sortReceivers) Less(i, j int) bool { return a[i].Amount < a[j].Amount }

type sortStrings []string

func (a sortStrings) Len() int           { return len(a) }
func (a sortStrings) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a sortStrings) Less(i, j int) bool { return a[i] < a[j] }
