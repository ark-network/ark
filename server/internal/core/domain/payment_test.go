package domain_test

import (
	"testing"

	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/stretchr/testify/require"
)

// x-only pubkey
const pubkey = "25a43cecfa0e1b1a4f72d64ad15f4cfa7a84d0723e8511c969aa543638ea9967"

var inputs = []domain.Vtxo{
	{
		VtxoKey: domain.VtxoKey{
			Txid: "0000000000000000000000000000000000000000000000000000000000000000",
			VOut: 0,
		},
		PubKey: pubkey,
		Amount: 1000,
	},
}

func TestPayment(t *testing.T) {
	t.Run("new_payment", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			payment, err := domain.NewPayment(inputs)
			require.NoError(t, err)
			require.NotNil(t, payment)
			require.NotEmpty(t, payment.Id)
			require.Exactly(t, inputs, payment.Inputs)
			require.Empty(t, payment.Receivers)
		})
	})

	t.Run("add_receivers", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			payment, err := domain.NewPayment(inputs)
			require.NoError(t, err)
			require.NotNil(t, payment)

			err = payment.AddReceivers([]domain.Receiver{
				{
					PubKey: pubkey,
					Amount: 450,
				},
				{
					PubKey: pubkey,
					Amount: 550,
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
