package note_test

import (
	"encoding/hex"
	"math"
	"testing"

	"github.com/ark-network/ark/common/note"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		value   uint32
		wantErr bool
	}{
		{
			name:    "Valid value",
			value:   100,
			wantErr: false,
		},
		{
			name:    "Zero value",
			value:   0,
			wantErr: false,
		},
		{
			name:    "Maximum uint32 value",
			value:   math.MaxUint32,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := note.New(tt.value)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, got)
				require.Equal(t, tt.value, got.Value)
				require.NotNil(t, got.Preimage)
				require.Len(t, got.Preimage, 32)
			}
		})
	}

	// Test for uniqueness of IDs
	t.Run("Unique preimage", func(t *testing.T) {
		preimageSet := make(map[string]bool)
		for i := 0; i < 1_000_000; i++ {
			data, err := note.New(100)
			require.NoError(t, err)
			require.False(t, preimageSet[hex.EncodeToString(data.Preimage[:])], "Generated duplicate preimage: %x", data.Preimage)
			preimageSet[hex.EncodeToString(data.Preimage[:])] = true
		}
	})
}

func TestNewFromString(t *testing.T) {
	tests := []struct {
		str              string
		expectedPreimage string
		expectedValue    uint32
	}{
		{
			str:              "arknote8rFzGqZsG9RCLripA6ez8d2hQEzFKsqCeiSnXhQj56Ysw7ZQT",
			expectedPreimage: "11d2a03264d0efd311d2a03264d0efd311d2a03264d0efd311d2a03264d0efd3",
			expectedValue:    900000,
		},
		{
			str:              "arknoteSkB92YpWm4Q2ijQHH34cqbKkCZWszsiQgHVjtNeFF2Cwp59D",
			expectedPreimage: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
			expectedValue:    1828932,
		},
	}

	for _, tt := range tests {
		t.Run(tt.str, func(t *testing.T) {
			preimage, err := hex.DecodeString(tt.expectedPreimage)
			require.NoError(t, err)
			var preimageArray [32]byte
			copy(preimageArray[:], preimage)

			n := &note.Note{
				Preimage: preimageArray,
				Value:    tt.expectedValue,
			}

			str := n.String()
			require.Equal(t, str, tt.str)

			note, err := note.NewFromString(tt.str)
			require.NoError(t, err)
			require.NotNil(t, note)
			require.Equal(t, preimageArray, note.Preimage)
			require.Equal(t, tt.expectedValue, note.Value)
		})
	}
}
