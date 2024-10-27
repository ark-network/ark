package voucher_test

import (
	"encoding/binary"
	"math"
	"testing"

	"github.com/ark-network/ark/common/voucher"
	"github.com/stretchr/testify/require"
)

func TestDataSerialize(t *testing.T) {
	tests := []struct {
		name    string
		voucher voucher.Data
		want    []byte
	}{
		{
			name:    "Valid voucher",
			voucher: voucher.Data{ID: 12345678901234567890, Value: 100},
			want: func() []byte {
				buf := make([]byte, 12)
				binary.BigEndian.PutUint64(buf[:8], 12345678901234567890)
				binary.BigEndian.PutUint32(buf[8:], 100)
				return buf
			}(),
		},
		{
			name:    "Zero values",
			voucher: voucher.Data{ID: 0, Value: 0},
			want:    make([]byte, 12),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.voucher.Serialize()
			require.Equal(t, tt.want, got)
		})
	}
}

func TestDataDeserialize(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    voucher.Data
		wantErr bool
	}{
		{
			name: "Valid data",
			data: func() []byte {
				buf := make([]byte, 12)
				binary.BigEndian.PutUint64(buf[:8], 12345678901234567890)
				binary.BigEndian.PutUint32(buf[8:], 100)
				return buf
			}(),
			want:    voucher.Data{ID: 12345678901234567890, Value: 100},
			wantErr: false,
		},
		{
			name:    "Zero values",
			data:    make([]byte, 12),
			want:    voucher.Data{ID: 0, Value: 0},
			wantErr: false,
		},
		{
			name:    "Invalid data length",
			data:    []byte{1, 2, 3},
			want:    voucher.Data{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got voucher.Data
			err := got.Deserialize(tt.data)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.want, got)
			}
		})
	}
}

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
			got, err := voucher.New(tt.value)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, got)
				require.Equal(t, tt.value, got.Value)
				require.NotZero(t, got.ID)
			}
		})
	}

	// Test for uniqueness of IDs
	t.Run("Unique IDs", func(t *testing.T) {
		idSet := make(map[uint64]bool)
		for i := 0; i < 1_000_000; i++ {
			data, err := voucher.New(100)
			require.NoError(t, err)
			require.False(t, idSet[data.ID], "Generated duplicate ID: %v", data.ID)
			idSet[data.ID] = true
		}
	})
}

func TestVoucherRoundtrip(t *testing.T) {
	tests := []struct {
		name    string
		voucher voucher.Voucher
	}{
		{
			name: "Valid voucher",
			voucher: voucher.Voucher{
				Data:      voucher.Data{ID: 12345678901234567890, Value: 100},
				Signature: []byte("test signature"),
			},
		},
		{
			name: "Voucher with empty signature",
			voucher: voucher.Voucher{
				Data:      voucher.Data{ID: 67899, Value: 200},
				Signature: []byte{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serialized := tt.voucher.Serialize()

			var deserialized voucher.Voucher
			err := deserialized.Deserialize(serialized)
			require.NoError(t, err)
			require.Equal(t, tt.voucher.Data.ID, deserialized.Data.ID)
			require.Equal(t, tt.voucher.Data.Value, deserialized.Data.Value)
			require.Equal(t, tt.voucher.Signature, deserialized.Signature)
		})
	}
}

func TestNewFromString(t *testing.T) {
	tests := []struct {
		name      string
		voucher   voucher.Voucher
		wantError bool
	}{
		{
			name: "Valid voucher",
			voucher: voucher.Voucher{
				Data:      voucher.Data{ID: 12345678901234567890, Value: 100},
				Signature: []byte("test signature"),
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			str := tt.voucher.String()

			deserialized, err := voucher.NewFromString(str)
			require.NoError(t, err)
			require.Equal(t, tt.voucher.Data, deserialized.Data)
			require.Equal(t, tt.voucher.Signature, deserialized.Signature)
		})
	}
}

func TestDataToVoucher(t *testing.T) {
	tests := []struct {
		name      string
		data      voucher.Data
		signature []byte
	}{
		{
			name:      "Valid voucher data and signature",
			data:      voucher.Data{ID: 12345678901234567890, Value: 100},
			signature: []byte("test signature"),
		},
		{
			name:      "Valid voucher data with empty signature",
			data:      voucher.Data{ID: 65992, Value: 200},
			signature: []byte{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			voucher := tt.data.ToVoucher(tt.signature)
			require.NotNil(t, voucher)
			require.Equal(t, tt.data, voucher.Data)
			require.Equal(t, tt.signature, voucher.Signature)
		})
	}
}

func TestDataHash(t *testing.T) {
	tests := []struct {
		name string
		data voucher.Data
	}{
		{
			name: "Valid voucher data",
			data: voucher.Data{ID: 12345678901234567890, Value: 100},
		},
		{
			name: "Zero values",
			data: voucher.Data{ID: 0, Value: 0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := tt.data.Hash()
			require.Len(t, hash, 32)

			// Verify that the hash is deterministic
			hash2 := tt.data.Hash()
			require.Equal(t, hash, hash2)

			// Verify that different details produce different hashes
			differentData := voucher.Data{ID: tt.data.ID + 1, Value: tt.data.Value}
			differentHash := differentData.Hash()
			require.NotEqual(t, hash, differentHash)
		})
	}
}
