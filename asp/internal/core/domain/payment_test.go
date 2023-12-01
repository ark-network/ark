package domain_test

import (
	"testing"

	"github.com/ark-network/ark/internal/core/domain"
	"github.com/stretchr/testify/require"
)

var inputs = []domain.Vtxo{
	{
		VtxoKey: domain.VtxoKey{
			Txid: "0000000000000000000000000000000000000000000000000000000000000000",
			VOut: 0,
		},
		Receiver: domain.Receiver{
			Pubkey: "030000000000000000000000000000000000000000000000000000000000000001",
			Amount: 500,
		},
	},
}

func TestPayment(t *testing.T) {
	t.Run("new_payment", func(t *testing.T) {
		t.Run("vaild", func(t *testing.T) {
			payment, err := domain.NewPayment(inputs)
			require.NoError(t, err)
			require.NotNil(t, payment)
			require.NotEmpty(t, payment.Id)
			require.Exactly(t, inputs, payment.Inputs)
			require.Empty(t, payment.Receivers)
		})

		t.Run("invaild", func(t *testing.T) {
			fixtures := []struct {
				inputs      []domain.Vtxo
				expectedErr string
			}{
				{
					inputs:      nil,
					expectedErr: "missing inputs",
				},
			}

			for _, f := range fixtures {
				payment, err := domain.NewPayment(f.inputs)
				require.EqualError(t, err, f.expectedErr)
				require.Nil(t, payment)
			}
		})
	})

	t.Run("add_receivers", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			payment, err := domain.NewPayment(inputs)
			require.NoError(t, err)
			require.NotNil(t, payment)

			err = payment.AddReceivers([]domain.Receiver{
				{
					Pubkey: "030000000000000000000000000000000000000000000000000000000000000001",
					Amount: 200,
				},
				{
					Pubkey: "020000000000000000000000000000000000000000000000000000000000000002",
					Amount: 300,
				},
			})
			require.NoError(t, err)
		})

		t.Run("invalid", func(t *testing.T) {
			fixtures := []struct {
				receivers   []domain.Receiver
				expectedErr string
			}{
				{
					receivers:   nil,
					expectedErr: "missing outputs",
				},
				{
					receivers: []domain.Receiver{
						{
							Pubkey: "030000000000000000000000000000000000000000000000000000000000000001",
							Amount: 100,
						},
					},
					expectedErr: "input and output amounts mismatch",
				},
			}

			payment, err := domain.NewPayment(inputs)
			require.NoError(t, err)
			require.NotNil(t, payment)

			for _, f := range fixtures {
				err := payment.AddReceivers(f.receivers)
				require.EqualError(t, err, f.expectedErr)
			}
		})
	})
}
