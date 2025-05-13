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
			require.False(t, preimageSet[hex.EncodeToString(data.Preimage)], "Generated duplicate preimage: %x", data.Preimage)
			preimageSet[hex.EncodeToString(data.Preimage)] = true
		}
	})
}

func TestNewFromString(t *testing.T) {
	tests := []struct {
		str              string
		expectedPreimage []byte
		expectedValue    uint32
	}{
		{
			str: "arknote8rFzGqZsG9RCLripA6ez8d2hQEzFKsqCeiSnXhQj56Ysw7ZQT",
			expectedPreimage: []byte{
				0x11, 0xd2, 0xa0, 0x32, 0x64, 0xd0, 0xef, 0xd3,
				0x11, 0xd2, 0xa0, 0x32, 0x64, 0xd0, 0xef, 0xd3,
				0x11, 0xd2, 0xa0, 0x32, 0x64, 0xd0, 0xef, 0xd3,
				0x11, 0xd2, 0xa0, 0x32, 0x64, 0xd0, 0xef, 0xd3,
			},
			expectedValue: 900000,
		},
		{
			str: "arknoteSkB92YpWm4Q2ijQHH34cqbKkCZWszsiQgHVjtNeFF2Cwp59D",
			expectedPreimage: []byte{
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
				0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
				0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
			},
			expectedValue: 1828932,
		},
	}

	for _, tt := range tests {
		t.Run(tt.str, func(t *testing.T) {
			n := &note.Note{
				Preimage: tt.expectedPreimage,
				Value:    tt.expectedValue,
			}

			str := n.String()
			require.Equal(t, str, tt.str)

			note, err := note.NewFromString(tt.str)
			require.NoError(t, err)
			require.NotNil(t, note)
			require.Equal(t, tt.expectedPreimage, note.Preimage)
			require.Equal(t, tt.expectedValue, note.Value)
		})
	}
}
