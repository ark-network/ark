package domain_test

import (
	"fmt"
	"testing"

	"github.com/ark-network/ark/common/descriptor"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/stretchr/testify/require"
)

var desc = fmt.Sprintf(
	descriptor.BoardingDescriptorTemplate,
	"030000000000000000000000000000000000000000000000000000000000000001",
	"0000000000000000000000000000000000000000000000000000000000000001",
	"0000000000000000000000000000000000000000000000000000000000000001",
	512,
	"0000000000000000000000000000000000000000000000000000000000000001",
)

var inputs = []domain.VtxoInput{
	{
		Vtxo: domain.Vtxo{
			VtxoKey: domain.VtxoKey{
				Txid: "0000000000000000000000000000000000000000000000000000000000000000",
				VOut: 0,
			},
			Receiver: domain.Receiver{
				Descriptor: desc,
				Amount:     1000,
			},
		},
		SignerPubkey: "030000000000000000000000000000000000000000000000000000000000000001",
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
					Descriptor: desc,
					Amount:     450,
				},
				{
					Descriptor: desc,
					Amount:     550,
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
