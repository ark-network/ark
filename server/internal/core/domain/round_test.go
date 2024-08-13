package domain_test

import (
	"fmt"
	"testing"

	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/stretchr/testify/require"
)

var (
	dustAmount = uint64(450)
	payments   = []domain.Payment{
		{
			Id: "0",
			Inputs: []domain.Vtxo{{
				VtxoKey: domain.VtxoKey{
					Txid: txid,
					VOut: 0,
				},
				Receiver: domain.Receiver{
					Pubkey: pubkey,
					Amount: 2000,
				},
			}},
			Receivers: []domain.Receiver{
				{
					Pubkey: pubkey,
					Amount: 700,
				},
				{
					Pubkey: pubkey,
					Amount: 700,
				},
				{
					Pubkey: pubkey,
					Amount: 600,
				},
			},
		},
		{
			Id: "1",
			Inputs: []domain.Vtxo{
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
						VOut: 0,
					},
					Receiver: domain.Receiver{
						Pubkey: pubkey,
						Amount: 1000,
					},
				},
			},
			Receivers: []domain.Receiver{{
				Pubkey: pubkey,
				Amount: 2000,
			}},
		},
	}
	emptyPtx       = "cHNldP8BAgQCAAAAAQQBAAEFAQABBgEDAfsEAgAAAAA="
	emptyTx        = "0200000000000000000000"
	txid           = "0000000000000000000000000000000000000000000000000000000000000000"
	pubkey         = "030000000000000000000000000000000000000000000000000000000000000001"
	congestionTree = tree.CongestionTree{
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
	connectors = []string{emptyPtx, emptyPtx, emptyPtx}
	forfeitTxs = []string{emptyPtx, emptyPtx, emptyPtx, emptyPtx, emptyPtx, emptyPtx, emptyPtx, emptyPtx, emptyPtx}
	poolTx     = emptyTx
)

func TestRound(t *testing.T) {
	testStartRegistration(t)

	testRegisterPayments(t)

	testStartFinalization(t)

	testEndFinalization(t)

	testFail(t)
}

func testStartRegistration(t *testing.T) {
	t.Run("start_registration", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			round := domain.NewRound(dustAmount)
			require.NotNil(t, round)
			require.NotEmpty(t, round.Id)
			require.Empty(t, round.Events())
			require.False(t, round.IsStarted())
			require.False(t, round.IsEnded())
			require.False(t, round.IsFailed())

			events, err := round.StartRegistration()
			require.NoError(t, err)
			require.Len(t, events, 1)
			require.True(t, round.IsStarted())
			require.False(t, round.IsEnded())
			require.False(t, round.IsFailed())

			event, ok := events[0].(domain.RoundStarted)
			require.True(t, ok)
			require.Equal(t, round.Id, event.Id)
			require.Equal(t, round.StartingTimestamp, event.Timestamp)
		})

		t.Run("invalid", func(t *testing.T) {
			fixtures := []struct {
				round       *domain.Round
				expectedErr string
			}{
				{
					round: &domain.Round{
						Id: "id",
						Stage: domain.Stage{
							Code:   domain.UndefinedStage,
							Failed: true,
						},
					},
					expectedErr: "not in a valid stage to start payment registration",
				},
				{
					round: &domain.Round{
						Id: "id",
						Stage: domain.Stage{
							Code: domain.RegistrationStage,
						},
					},
					expectedErr: "not in a valid stage to start payment registration",
				},
				{
					round: &domain.Round{
						Id: "id",
						Stage: domain.Stage{
							Code: domain.FinalizationStage,
						},
					},
					expectedErr: "not in a valid stage to start payment registration",
				},
			}

			for _, f := range fixtures {
				events, err := f.round.StartRegistration()
				require.EqualError(t, err, f.expectedErr)
				require.Empty(t, events)
			}
		})
	})
}

func testRegisterPayments(t *testing.T) {
	t.Run("register_payments", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			round := domain.NewRound(dustAmount)
			events, err := round.StartRegistration()
			require.NoError(t, err)
			require.NotEmpty(t, events)

			events, err = round.RegisterPayments(payments)
			require.NoError(t, err)
			require.Len(t, events, 1)
			require.Condition(t, func() bool {
				for _, payment := range payments {
					_, ok := round.Payments[payment.Id]
					if !ok {
						return false
					}
				}
				return true
			})

			event, ok := events[0].(domain.PaymentsRegistered)
			require.True(t, ok)
			require.Equal(t, round.Id, event.Id)
			require.Equal(t, payments, event.Payments)
		})

		t.Run("invalid", func(t *testing.T) {
			fixtures := []struct {
				round       *domain.Round
				payments    []domain.Payment
				expectedErr string
			}{
				{
					round: &domain.Round{
						Id:    "id",
						Stage: domain.Stage{},
					},
					payments:    payments,
					expectedErr: "not in a valid stage to register payments",
				},
				{
					round: &domain.Round{
						Id: "id",
						Stage: domain.Stage{
							Code:   domain.RegistrationStage,
							Failed: true,
						},
					},
					payments:    payments,
					expectedErr: "not in a valid stage to register payments",
				},
				{
					round: &domain.Round{
						Id: "id",
						Stage: domain.Stage{
							Code: domain.FinalizationStage,
						},
					},
					payments:    payments,
					expectedErr: "not in a valid stage to register payments",
				},
				{
					round: &domain.Round{
						Id: "id",
						Stage: domain.Stage{
							Code: domain.RegistrationStage,
						},
					},
					payments:    nil,
					expectedErr: "missing payments to register",
				},
			}

			for _, f := range fixtures {
				events, err := f.round.RegisterPayments(f.payments)
				require.EqualError(t, err, f.expectedErr)
				require.Empty(t, events)
			}
		})
	})
}

func testStartFinalization(t *testing.T) {
	t.Run("start_finalization", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			round := domain.NewRound(dustAmount)
			events, err := round.StartRegistration()
			require.NoError(t, err)
			require.NotEmpty(t, events)

			events, err = round.RegisterPayments(payments)
			require.NoError(t, err)
			require.NotEmpty(t, events)

			events, err = round.StartFinalization("", connectors, congestionTree, poolTx)
			require.NoError(t, err)
			require.Len(t, events, 1)
			require.True(t, round.IsStarted())
			require.False(t, round.IsEnded())
			require.False(t, round.IsFailed())

			event, ok := events[0].(domain.RoundFinalizationStarted)
			require.True(t, ok)
			require.Equal(t, round.Id, event.Id)
			require.Exactly(t, connectors, event.Connectors)
			require.Exactly(t, congestionTree, event.CongestionTree)
			require.Exactly(t, poolTx, event.PoolTx)
		})

		t.Run("invalid", func(t *testing.T) {
			paymentsById := map[string]domain.Payment{}
			for _, p := range payments {
				paymentsById[p.Id] = p
			}
			fixtures := []struct {
				round       *domain.Round
				connectors  []string
				tree        tree.CongestionTree
				poolTx      string
				expectedErr string
			}{
				{
					round: &domain.Round{
						Id: "0",
						Stage: domain.Stage{
							Code: domain.RegistrationStage,
						},
						Payments: paymentsById,
					},
					connectors:  connectors,
					tree:        congestionTree,
					poolTx:      "",
					expectedErr: "missing unsigned pool tx",
				},
				{
					round: &domain.Round{
						Id: "0",
						Stage: domain.Stage{
							Code: domain.RegistrationStage,
						},
						Payments: nil,
					},
					connectors:  connectors,
					tree:        congestionTree,
					poolTx:      poolTx,
					expectedErr: "no payments registered",
				},
				{
					round: &domain.Round{
						Id: "0",
						Stage: domain.Stage{
							Code: domain.UndefinedStage,
						},
						Payments: paymentsById,
					},
					connectors:  connectors,
					tree:        congestionTree,
					poolTx:      poolTx,
					expectedErr: "not in a valid stage to start payment finalization",
				},
				{
					round: &domain.Round{
						Id: "0",
						Stage: domain.Stage{
							Code:   domain.RegistrationStage,
							Failed: true,
						},
						Payments: paymentsById,
					},
					connectors:  connectors,
					tree:        congestionTree,
					poolTx:      poolTx,
					expectedErr: "not in a valid stage to start payment finalization",
				},
				{
					round: &domain.Round{
						Id: "0",
						Stage: domain.Stage{
							Code: domain.FinalizationStage,
						},
						Payments: paymentsById,
					},
					connectors:  connectors,
					tree:        congestionTree,
					poolTx:      poolTx,
					expectedErr: "not in a valid stage to start payment finalization",
				},
			}

			for _, f := range fixtures {
				// TODO fix this
				events, err := f.round.StartFinalization("", f.connectors, f.tree, f.poolTx)
				require.EqualError(t, err, f.expectedErr)
				require.Empty(t, events)
			}
		})
	})
}

func testEndFinalization(t *testing.T) {
	t.Run("end_registration", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			round := domain.NewRound(dustAmount)
			events, err := round.StartRegistration()
			require.NoError(t, err)
			require.NotEmpty(t, events)

			events, err = round.RegisterPayments(payments)
			require.NoError(t, err)
			require.NotEmpty(t, events)

			events, err = round.StartFinalization("", connectors, congestionTree, poolTx)
			require.NoError(t, err)
			require.NotEmpty(t, events)

			events, err = round.EndFinalization(forfeitTxs, txid)
			require.NoError(t, err)
			require.Len(t, events, 1)
			require.False(t, round.IsStarted())
			require.True(t, round.IsEnded())
			require.False(t, round.IsFailed())

			event, ok := events[0].(domain.RoundFinalized)
			require.True(t, ok)
			require.Equal(t, round.Id, event.Id)
			require.Exactly(t, txid, event.Txid)
			require.Exactly(t, forfeitTxs, event.ForfeitTxs)
			require.Exactly(t, round.EndingTimestamp, event.Timestamp)
		})

		t.Run("invalid", func(t *testing.T) {
			paymentsById := map[string]domain.Payment{}
			for _, p := range payments {
				paymentsById[p.Id] = p
			}
			fixtures := []struct {
				round       *domain.Round
				forfeitTxs  []string
				txid        string
				expectedErr string
			}{
				{
					round: &domain.Round{
						Id: "0",
						Stage: domain.Stage{
							Code: domain.FinalizationStage,
						},
					},
					forfeitTxs:  nil,
					txid:        txid,
					expectedErr: "missing list of signed forfeit txs",
				},
				{
					round: &domain.Round{
						Id: "0",
						Stage: domain.Stage{
							Code: domain.FinalizationStage,
						},
					},
					forfeitTxs:  forfeitTxs,
					txid:        "",
					expectedErr: "missing pool txid",
				},
				{
					round: &domain.Round{
						Id: "0",
					},
					forfeitTxs:  forfeitTxs,
					txid:        txid,
					expectedErr: "not in a valid stage to end payment finalization",
				},
				{
					round: &domain.Round{
						Id: "0",
						Stage: domain.Stage{
							Code: domain.RegistrationStage,
						},
					},
					forfeitTxs:  forfeitTxs,
					txid:        txid,
					expectedErr: "not in a valid stage to end payment finalization",
				},
				{
					round: &domain.Round{
						Id: "0",
						Stage: domain.Stage{
							Code:   domain.FinalizationStage,
							Failed: true,
						},
					},
					forfeitTxs:  []string{emptyPtx, emptyPtx, emptyPtx, emptyPtx},
					txid:        txid,
					expectedErr: "not in a valid stage to end payment finalization",
				},
				{
					round: &domain.Round{
						Id: "0",
						Stage: domain.Stage{
							Code:  domain.FinalizationStage,
							Ended: true,
						},
					},
					forfeitTxs:  []string{emptyPtx, emptyPtx, emptyPtx, emptyPtx},
					txid:        txid,
					expectedErr: "round already finalized",
				},
			}

			for _, f := range fixtures {
				events, err := f.round.EndFinalization(f.forfeitTxs, f.txid)
				require.EqualError(t, err, f.expectedErr)
				require.Empty(t, events)
			}
		})
	})
}

func testFail(t *testing.T) {
	t.Run("fail", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			round := domain.NewRound(dustAmount)
			events, err := round.StartRegistration()
			require.NoError(t, err)
			require.NotEmpty(t, events)

			events, err = round.RegisterPayments(payments)
			require.NoError(t, err)
			require.NotEmpty(t, events)

			reason := fmt.Errorf("some valid reason")
			events = round.Fail(reason)
			require.Len(t, events, 1)
			require.False(t, round.IsStarted())
			require.False(t, round.IsEnded())
			require.True(t, round.IsFailed())

			event, ok := events[0].(domain.RoundFailed)
			require.True(t, ok)
			require.Exactly(t, round.Id, event.Id)
			require.Exactly(t, round.EndingTimestamp, event.Timestamp)
			require.EqualError(t, reason, event.Err)

			events = round.Fail(reason)
			require.Empty(t, events)
		})
	})
}
