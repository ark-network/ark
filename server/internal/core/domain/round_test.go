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
	requests   = []domain.TxRequest{
		{
			Id: "0",
			Inputs: []domain.Vtxo{
				{
					VtxoKey: domain.VtxoKey{
						Txid: txid,
						VOut: 0,
					},
					PubKey: pubkey,
					Amount: 2000,
				},
			},
			Receivers: []domain.Receiver{
				{
					PubKey: pubkey,
					Amount: 700,
				},
				{
					PubKey: pubkey,
					Amount: 700,
				},
				{
					PubKey: pubkey,
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
					PubKey: pubkey,
					Amount: 1000,
				},
				{
					VtxoKey: domain.VtxoKey{
						Txid: txid,
						VOut: 0,
					},
					PubKey: pubkey,
					Amount: 1000,
				},
			},
			Receivers: []domain.Receiver{{
				PubKey: pubkey,
				Amount: 2000,
			}},
		},
	}
	emptyPtx = "cHNldP8BAgQCAAAAAQQBAAEFAQABBgEDAfsEAgAAAAA="
	emptyTx  = "0200000000000000000000"
	txid     = "0000000000000000000000000000000000000000000000000000000000000000"
	txid2    = "0000000000000000000000000000000000000000000000000000000000000001"
	vtxoTree = tree.TxTree{
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
	connectors = tree.TxTree{
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
	}
	forfeitTxs = []string{emptyPtx, emptyPtx, emptyPtx, emptyPtx, emptyPtx, emptyPtx, emptyPtx, emptyPtx, emptyPtx}
	roundTx    = emptyTx
)

func TestRound(t *testing.T) {
	testStartRegistration(t)

	testRegisterTxRequests(t)

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
					expectedErr: "not in a valid stage to start tx requests registration",
				},
				{
					round: &domain.Round{
						Id: "id",
						Stage: domain.Stage{
							Code: domain.RegistrationStage,
						},
					},
					expectedErr: "not in a valid stage to start tx requests registration",
				},
				{
					round: &domain.Round{
						Id: "id",
						Stage: domain.Stage{
							Code: domain.FinalizationStage,
						},
					},
					expectedErr: "not in a valid stage to start tx requests registration",
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

func testRegisterTxRequests(t *testing.T) {
	t.Run("register_tx_requests", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			round := domain.NewRound(dustAmount)
			events, err := round.StartRegistration()
			require.NoError(t, err)
			require.NotEmpty(t, events)

			events, err = round.RegisterTxRequests(requests)
			require.NoError(t, err)
			require.Len(t, events, 1)
			require.Condition(t, func() bool {
				for _, request := range requests {
					_, ok := round.TxRequests[request.Id]
					if !ok {
						return false
					}
				}
				return true
			})

			event, ok := events[0].(domain.TxRequestsRegistered)
			require.True(t, ok)
			require.Equal(t, round.Id, event.Id)
			require.Equal(t, requests, event.TxRequests)
		})

		t.Run("invalid", func(t *testing.T) {
			fixtures := []struct {
				round       *domain.Round
				requests    []domain.TxRequest
				expectedErr string
			}{
				{
					round: &domain.Round{
						Id:    "id",
						Stage: domain.Stage{},
					},
					requests:    requests,
					expectedErr: "not in a valid stage to register tx requests",
				},
				{
					round: &domain.Round{
						Id: "id",
						Stage: domain.Stage{
							Code:   domain.RegistrationStage,
							Failed: true,
						},
					},
					requests:    requests,
					expectedErr: "not in a valid stage to register tx requests",
				},
				{
					round: &domain.Round{
						Id: "id",
						Stage: domain.Stage{
							Code: domain.FinalizationStage,
						},
					},
					requests:    requests,
					expectedErr: "not in a valid stage to register tx requests",
				},
				{
					round: &domain.Round{
						Id: "id",
						Stage: domain.Stage{
							Code: domain.RegistrationStage,
						},
					},
					requests:    nil,
					expectedErr: "missing tx requests to register",
				},
			}

			for _, f := range fixtures {
				events, err := f.round.RegisterTxRequests(f.requests)
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

			events, err = round.RegisterTxRequests(requests)
			require.NoError(t, err)
			require.NotEmpty(t, events)

			events, err = round.StartFinalization("", connectors, vtxoTree, roundTx, map[string]domain.Outpoint{
				txid: {
					Txid: txid,
					VOut: 0,
				},
				txid2: {
					Txid: txid2,
					VOut: 1,
				},
			})
			require.NoError(t, err)
			require.Len(t, events, 1)
			require.True(t, round.IsStarted())
			require.False(t, round.IsEnded())
			require.False(t, round.IsFailed())

			event, ok := events[0].(domain.RoundFinalizationStarted)
			require.True(t, ok)
			require.Equal(t, round.Id, event.Id)
			require.Exactly(t, connectors, event.Connectors)
			require.Exactly(t, vtxoTree, event.VtxoTree)
			require.Exactly(t, roundTx, event.RoundTx)
		})

		t.Run("invalid", func(t *testing.T) {
			requestsById := map[string]domain.TxRequest{}
			for _, p := range requests {
				requestsById[p.Id] = p
			}
			fixtures := []struct {
				round       *domain.Round
				connectors  tree.TxTree
				tree        tree.TxTree
				roundTx     string
				expectedErr string
			}{
				{
					round: &domain.Round{
						Id: "0",
						Stage: domain.Stage{
							Code: domain.RegistrationStage,
						},
						TxRequests: requestsById,
					},
					connectors:  connectors,
					tree:        vtxoTree,
					roundTx:     "",
					expectedErr: "missing unsigned round tx",
				},
				{
					round: &domain.Round{
						Id: "0",
						Stage: domain.Stage{
							Code: domain.RegistrationStage,
						},
						TxRequests: nil,
					},
					connectors:  connectors,
					tree:        vtxoTree,
					roundTx:     roundTx,
					expectedErr: "no tx requests registered",
				},
				{
					round: &domain.Round{
						Id: "0",
						Stage: domain.Stage{
							Code: domain.UndefinedStage,
						},
						TxRequests: requestsById,
					},
					connectors:  connectors,
					tree:        vtxoTree,
					roundTx:     roundTx,
					expectedErr: "not in a valid stage to start finalization",
				},
				{
					round: &domain.Round{
						Id: "0",
						Stage: domain.Stage{
							Code:   domain.RegistrationStage,
							Failed: true,
						},
						TxRequests: requestsById,
					},
					connectors:  connectors,
					tree:        vtxoTree,
					roundTx:     roundTx,
					expectedErr: "not in a valid stage to start finalization",
				},
				{
					round: &domain.Round{
						Id: "0",
						Stage: domain.Stage{
							Code: domain.FinalizationStage,
						},
						TxRequests: requestsById,
					},
					connectors:  connectors,
					tree:        vtxoTree,
					roundTx:     roundTx,
					expectedErr: "not in a valid stage to start finalization",
				},
			}

			for _, f := range fixtures {
				// TODO fix this
				events, err := f.round.StartFinalization("", f.connectors, f.tree, f.roundTx, map[string]domain.Outpoint{
					txid: {
						Txid: txid,
						VOut: 0,
					},
				})
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

			events, err = round.RegisterTxRequests(requests)
			require.NoError(t, err)
			require.NotEmpty(t, events)

			events, err = round.StartFinalization("", connectors, vtxoTree, roundTx, map[string]domain.Outpoint{
				txid: {
					Txid: txid,
					VOut: 0,
				},
			})
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
			requestsById := map[string]domain.TxRequest{}
			for _, p := range requests {
				requestsById[p.Id] = p
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
						TxRequests: requestsById,
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
					expectedErr: "missing round txid",
				},
				{
					round: &domain.Round{
						Id: "0",
					},
					forfeitTxs:  forfeitTxs,
					txid:        txid,
					expectedErr: "not in a valid stage to end finalization",
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
					expectedErr: "not in a valid stage to end finalization",
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
					expectedErr: "not in a valid stage to end finalization",
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

			events, err = round.RegisterTxRequests(requests)
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
