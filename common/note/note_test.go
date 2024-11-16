package note_test

import (
	"encoding/binary"
	"math"
	"testing"

	"github.com/ark-network/ark/common/note"
	"github.com/stretchr/testify/require"
)

func TestDataSerialize(t *testing.T) {
	tests := []struct {
		name string
		note note.Data
		want []byte
	}{
		{
			name: "Valid note",
			note: note.Data{ID: 12345678901234567890, Value: 100},
			want: func() []byte {
				buf := make([]byte, 12)
				binary.BigEndian.PutUint64(buf[:8], 12345678901234567890)
				binary.BigEndian.PutUint32(buf[8:], 100)
				return buf
			}(),
		},
		{
			name: "Zero values",
			note: note.Data{ID: 0, Value: 0},
			want: make([]byte, 12),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.note.Serialize()
			require.Equal(t, tt.want, got)
		})
	}
}

func TestDataDeserialize(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    note.Data
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
			want:    note.Data{ID: 12345678901234567890, Value: 100},
			wantErr: false,
		},
		{
			name:    "Zero values",
			data:    make([]byte, 12),
			want:    note.Data{ID: 0, Value: 0},
			wantErr: false,
		},
		{
			name:    "Invalid data length",
			data:    []byte{1, 2, 3},
			want:    note.Data{},
			wantErr: true,
		},
		{
			name:    "Nil data",
			data:    nil,
			want:    note.Data{},
			wantErr: true,
		},
		{
			name:    "Too long data",
			data:    make([]byte, 20),
			want:    note.Data{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got note.Data
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
			got, err := note.New(tt.value)
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
			data, err := note.New(100)
			require.NoError(t, err)
			require.False(t, idSet[data.ID], "Generated duplicate ID: %v", data.ID)
			idSet[data.ID] = true
		}
	})
}

func TestNoteRoundtrip(t *testing.T) {
	tests := []struct {
		name string
		note note.Note
	}{
		{
			name: "Valid note",
			note: note.Note{
				Data:      note.Data{ID: 12345678901234567890, Value: 100},
				Signature: []byte("test signature"),
			},
		},
		{
			name: "Note with nil signature",
			note: note.Note{
				Data:      note.Data{ID: 67899, Value: 200000},
				Signature: nil,
			},
		},
		{
			name: "Note with large signature",
			note: note.Note{
				Data:      note.Data{ID: 67899, Value: 200},
				Signature: make([]byte, 1000),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serialized := tt.note.Serialize()

			var deserialized note.Note
			err := deserialized.Deserialize(serialized)
			require.NoError(t, err)
			require.Equal(t, tt.note.Data.ID, deserialized.Data.ID)
			require.Equal(t, tt.note.Data.Value, deserialized.Data.Value)
			require.Equal(t, tt.note.Signature, deserialized.Signature)
		})
	}
}

func TestNewFromString(t *testing.T) {
	tests := []struct {
		str           string
		expectedID    uint64
		expectedValue uint32
	}{
		{
			str:           "arknote2iqtKmdVWDNo8aXT7HHWLxcZovseWBqAEf2Q4SwhqMQHRyuhLQSukyNtmJzrnPHEcLGDsvxVsmndw8e8m4AFy2FbSw8Q6MA6uYCZQeY6",
			expectedID:    0x11d2a03264d0efd3,
			expectedValue: 900000,
		},
		{
			str:           "arknoteDyxaEGpxuGNNy4L6B45vDarZzY8ChLST7AD4VYshjCNByz1p3ayWwrK6QN696Us1uMwP6frxBu171ESuqU1AjrWzXgoPYnNoogLbcYps",
			expectedID:    0x8668bd0f324d8ec7,
			expectedValue: 1828932,
		},
	}

	for _, tt := range tests {
		t.Run(tt.str, func(t *testing.T) {
			note, err := note.NewFromString(tt.str)
			require.NoError(t, err)
			require.NotNil(t, note)
			require.Len(t, note.Signature, 64)
			require.Equal(t, tt.expectedID, note.Data.ID)
			require.Equal(t, tt.expectedValue, note.Data.Value)
		})
	}
}

func TestDataToNote(t *testing.T) {
	tests := []struct {
		name      string
		data      note.Data
		signature []byte
	}{
		{
			name:      "Valid note data and signature",
			data:      note.Data{ID: 12345678901234567890, Value: 100},
			signature: []byte("test signature"),
		},
		{
			name:      "Valid note data with empty signature",
			data:      note.Data{ID: 65992, Value: 200},
			signature: []byte{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			note := tt.data.ToNote(tt.signature)
			require.NotNil(t, note)
			require.Equal(t, tt.data, note.Data)
			require.Equal(t, tt.signature, note.Signature)
		})
	}
}

func TestDataHash(t *testing.T) {
	tests := []struct {
		name string
		data note.Data
	}{
		{
			name: "Valid note data",
			data: note.Data{ID: 12345678901234567890, Value: 100},
		},
		{
			name: "Zero values",
			data: note.Data{ID: 0, Value: 0},
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
			differentData := note.Data{ID: tt.data.ID + 1, Value: tt.data.Value}
			differentHash := differentData.Hash()
			require.NotEqual(t, hash, differentHash)
		})
	}
}
