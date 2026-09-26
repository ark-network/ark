package application

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMaxOffchainTxFee(t *testing.T) {
	for _, test := range []struct {
		minAmount int64
		want      int64
	}{
		{minAmount: -1, want: 0},
		{minAmount: 0, want: 0},
		{minAmount: 1, want: 0},
		{minAmount: 330, want: 329},
		{minAmount: 1000, want: 999},
	} {
		require.Equal(t, test.want, maxOffchainTxFee(test.minAmount))
	}
}
