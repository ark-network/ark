package db_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/ark-network/ark/common/descriptor"
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
	pubkey1  = "00000000000000000000000000000000000000000000000000000000000000001"
	pubkey2  = "00000000000000000000000000000000000000000000000000000000000000002"
)

var desc1 = fmt.Sprintf(
	descriptor.DefaultVtxoDescriptorTemplate,
	randomString(66),
	pubkey1,
	pubkey1,
	512,
	pubkey1,
)

var desc2 = fmt.Sprintf(
	descriptor.DefaultVtxoDescriptorTemplate,
	randomString(66),
	pubkey2,
	pubkey2,
	512,
	pubkey2,
)

var congestionTree = [][]tree.Node{
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
				DataStoreConfig:  []interface{}{dbDir, "file://sqlite/migration"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, err := db.NewService(tt.config)
			require.NoError(t, err)
			require.NotNil(t, svc)

			testRoundEventRepository(t, svc)
			testRoundRepository(t, svc)
			testVtxoRepository(t, svc)

			time.Sleep(5 * time.Second)
			svc.Close()
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
						Id:             "1ea610ff-bf3e-4068-9bfd-b6c3f553467e",
						CongestionTree: congestionTree,
						Connectors:     []string{emptyPtx, emptyPtx},
						RoundTx:        emptyTx,
					},
				},
				handler: func(round *domain.Round) {
					require.NotNil(t, round)
					require.Len(t, round.Events(), 2)
					require.Len(t, round.CongestionTree, 3)
					require.Equal(t, round.CongestionTree.NumberOfNodes(), 7)
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
						Id:             "7578231e-428d-45ae-aaa4-e62c77ad5cec",
						CongestionTree: congestionTree,
						Connectors:     []string{emptyPtx, emptyPtx},
						RoundTx:        emptyTx,
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
			domain.PaymentsRegistered{
				Id: roundId,
				Payments: []domain.Payment{
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
								Receiver: domain.Receiver{
									Descriptor: randomString(120),
									Amount:     300,
								},
							},
						},
						Receivers: []domain.Receiver{{
							Descriptor: randomString(120),
							Amount:     300,
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
								Receiver: domain.Receiver{
									Descriptor: randomString(120),
									Amount:     600,
								},
							},
						},
						Receivers: []domain.Receiver{
							{
								Descriptor: randomString(120),
								Amount:     400,
							},
							{
								Descriptor: randomString(120),
								Amount:     200,
							},
						},
					},
				},
			},
			domain.RoundFinalizationStarted{
				Id:             roundId,
				CongestionTree: congestionTree,
				Connectors:     []string{emptyPtx, emptyPtx},
				RoundTx:        emptyTx,
			},
		}
		events = append(events, newEvents...)
		updatedRound := domain.NewRoundFromEvents(events)
		for _, pay := range updatedRound.Payments {
			err = svc.Vtxos().AddVtxos(ctx, pay.Inputs)
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
				Receiver: domain.Receiver{
					Descriptor: desc1,
					Amount:     1000,
				},
			},
			{
				VtxoKey: domain.VtxoKey{
					Txid: randomString(32),
					VOut: 1,
				},
				Receiver: domain.Receiver{
					Descriptor: desc1,
					Amount:     2000,
				},
			},
		}
		newVtxos := append(userVtxos, domain.Vtxo{
			VtxoKey: domain.VtxoKey{
				Txid: randomString(32),
				VOut: 1,
			},
			Receiver: domain.Receiver{
				Descriptor: desc2,
				Amount:     2000,
			},
		})

		vtxoKeys := make([]domain.VtxoKey, 0, len(userVtxos))
		for _, v := range userVtxos {
			vtxoKeys = append(vtxoKeys, v.VtxoKey)
		}

		vtxos, err := svc.Vtxos().GetVtxos(ctx, vtxoKeys)
		require.Error(t, err)
		require.Empty(t, vtxos)

		spendableVtxos, spentVtxos, err := svc.Vtxos().GetAllVtxos(ctx, pubkey1)
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

		spendableVtxos, spentVtxos, err = svc.Vtxos().GetAllVtxos(ctx, pubkey1)
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

		spendableVtxos, spentVtxos, err = svc.Vtxos().GetAllVtxos(ctx, pubkey1)
		require.NoError(t, err)
		require.Exactly(t, vtxos[1:], spendableVtxos)
		require.Len(t, spentVtxos, len(vtxoKeys[:1]))
	})
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

		for k, v := range expected.Payments {
			gotValue, ok := got.Payments[k]
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

		if !reflect.DeepEqual(expected.CongestionTree, got.CongestionTree) {
			return false
		}

		if len(expected.Connectors) > 0 {
			expectedConnectors := sortStrings(expected.Connectors)
			gotConnectors := sortStrings(got.Connectors)

			sort.Sort(expectedConnectors)
			sort.Sort(gotConnectors)

			if !reflect.DeepEqual(expectedConnectors, gotConnectors) {
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
