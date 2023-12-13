package db_test

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/ark-network/ark/internal/core/domain"
	"github.com/ark-network/ark/internal/core/ports"
	"github.com/ark-network/ark/internal/infrastructure/db"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	emptyPtx = "cHNldP8BAgQCAAAAAQQBAAEFAQABBgEDAfsEAgAAAAA="
	emptyTx  = "0200000000000000000000"
	txid     = "00000000000000000000000000000000000000000000000000000000000000000"
	pubkey   = "0300000000000000000000000000000000000000000000000000000000000000001"
)

var congestionTree = [][]domain.Node{
	{
		{
			Txid:       txid,
			Tx:         emptyPtx,
			ParentTxid: txid,
		},
	},
	{
		{
			Txid:       txid,
			Tx:         emptyPtx,
			ParentTxid: txid,
		},
		{
			Txid:       txid,
			Tx:         emptyPtx,
			ParentTxid: txid,
		},
	},
	{
		{
			Txid:       txid,
			Tx:         emptyPtx,
			ParentTxid: txid,
		},
		{
			Txid:       txid,
			Tx:         emptyPtx,
			ParentTxid: txid,
		},
		{
			Txid:       txid,
			Tx:         emptyPtx,
			ParentTxid: txid,
		},
		{
			Txid:       txid,
			Tx:         emptyPtx,
			ParentTxid: txid,
		},
	},
}

func TestService(t *testing.T) {
	tests := []struct {
		name   string
		config db.ServiceConfig
	}{
		{
			name: "repo_manager_with_badger_stores",
			config: db.ServiceConfig{
				EventStoreType:   "badger",
				RoundStoreType:   "badger",
				VtxoStoreType:    "badger",
				EventStoreConfig: []interface{}{"", nil},
				RoundStoreConfig: []interface{}{"", nil},
				VtxoStoreConfig:  []interface{}{"", nil},
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
						PoolTx:         emptyTx,
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
						PoolTx:         emptyTx,
					},
					domain.RoundFinalized{
						Id:         "7578231e-428d-45ae-aaa4-e62c77ad5cec",
						Txid:       txid,
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

			err := svc.Events().Save(ctx, f.roundId, f.events...)
			require.NoError(t, err)

			round, err := svc.Events().Load(ctx, f.roundId)
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

		currentRound, err := svc.Rounds().GetCurrentRound(ctx)
		require.NoError(t, err)
		require.NotNil(t, currentRound)
		require.Condition(t, roundsMatch(*round, *currentRound))

		roundById, err := svc.Rounds().GetRoundWithId(ctx, roundId)
		require.NoError(t, err)
		require.NotNil(t, roundById)
		require.Condition(t, roundsMatch(*round, *roundById))

		newEvents := []domain.RoundEvent{
			domain.PaymentsRegistered{
				Id: roundId,
				Payments: []domain.Payment{
					{
						Id:        uuid.New().String(),
						Inputs:    []domain.Vtxo{{}},
						Receivers: []domain.Receiver{{}},
					},
					{
						Id:        uuid.New().String(),
						Inputs:    []domain.Vtxo{{}},
						Receivers: []domain.Receiver{{}, {}, {}},
					},
				},
			},
			domain.RoundFinalizationStarted{
				Id:             roundId,
				CongestionTree: congestionTree,
				Connectors:     []string{emptyPtx, emptyPtx},
				PoolTx:         emptyTx,
			},
		}
		events = append(events, newEvents...)
		updatedRound := domain.NewRoundFromEvents(events)

		err = svc.Rounds().AddOrUpdateRound(ctx, *updatedRound)
		require.NoError(t, err)

		currentRound, err = svc.Rounds().GetCurrentRound(ctx)
		require.NoError(t, err)
		require.NotNil(t, currentRound)
		require.Condition(t, roundsMatch(*updatedRound, *currentRound))

		roundById, err = svc.Rounds().GetRoundWithId(ctx, updatedRound.Id)
		require.NoError(t, err)
		require.NotNil(t, currentRound)
		require.Condition(t, roundsMatch(*updatedRound, *roundById))

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

		currentRound, err = svc.Rounds().GetCurrentRound(ctx)
		require.Error(t, err)
		require.Nil(t, currentRound)

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

		newVtxos := []domain.Vtxo{
			{
				VtxoKey: domain.VtxoKey{
					Txid: txid,
					VOut: 0,
				},
				Receiver: domain.Receiver{
					Pubkey: pubkey,
					Amount: 1000,
				},
			},
			{
				VtxoKey: domain.VtxoKey{
					Txid: txid,
					VOut: 1,
				},
				Receiver: domain.Receiver{
					Pubkey: pubkey,
					Amount: 2000,
				},
			},
		}
		vtxoKeys := make([]domain.VtxoKey, 0, len(newVtxos))
		for _, v := range newVtxos {
			vtxoKeys = append(vtxoKeys, v.VtxoKey)
		}

		vtxos, err := svc.Vtxos().GetVtxos(ctx, vtxoKeys)
		require.Error(t, err)
		require.Empty(t, vtxos)

		spendableVtxos, err := svc.Vtxos().GetSpendableVtxosWithPubkey(ctx, pubkey)
		require.NoError(t, err)
		require.Empty(t, spendableVtxos)

		err = svc.Vtxos().AddVtxos(ctx, newVtxos)
		require.NoError(t, err)

		vtxos, err = svc.Vtxos().GetVtxos(ctx, vtxoKeys)
		require.NoError(t, err)
		require.Exactly(t, vtxos, newVtxos)

		spendableVtxos, err = svc.Vtxos().GetSpendableVtxosWithPubkey(ctx, pubkey)
		require.NoError(t, err)
		require.Exactly(t, vtxos, spendableVtxos)

		err = svc.Vtxos().SpendVtxos(ctx, vtxoKeys[:1])
		require.NoError(t, err)

		spentVtxos, err := svc.Vtxos().GetVtxos(ctx, vtxoKeys[:1])
		require.NoError(t, err)
		require.Len(t, spentVtxos, len(vtxoKeys[:1]))
		for _, v := range spentVtxos {
			require.True(t, v.Spent)
		}

		spendableVtxos, err = svc.Vtxos().GetSpendableVtxosWithPubkey(ctx, pubkey)
		require.NoError(t, err)
		require.Exactly(t, vtxos[1:], spendableVtxos)
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
		if !reflect.DeepEqual(expected.Payments, got.Payments) {
			return false
		}
		if expected.Txid != got.Txid {
			return false
		}
		if expected.TxHex != got.TxHex {
			return false
		}
		if !reflect.DeepEqual(expected.ForfeitTxs, got.ForfeitTxs) {
			return false
		}
		if !reflect.DeepEqual(expected.CongestionTree, got.CongestionTree) {
			return false
		}
		if !reflect.DeepEqual(expected.Connectors, got.Connectors) {
			return false
		}
		if expected.Version != got.Version {
			return false
		}
		return true
	}
}
