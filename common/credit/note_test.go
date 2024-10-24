package credit_test

import (
	"encoding/binary"
	"math"
	"testing"

	"github.com/ark-network/ark/common/credit"
	"github.com/stretchr/testify/require"
)

func TestNoteDetails_Serialize(t *testing.T) {
	tests := []struct {
		name string
		note credit.NoteDetails
		want []byte
	}{
		{
			name: "Valid note",
			note: credit.NoteDetails{ID: 12345, Value: 100},
			want: func() []byte {
				buf := make([]byte, 8)
				binary.BigEndian.PutUint64(buf, uint64(12345)<<32|uint64(100))
				return buf
			}(),
		},
		{
			name: "Zero values",
			note: credit.NoteDetails{ID: 0, Value: 0},
			want: make([]byte, 8),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.note.Serialize()
			require.Equal(t, tt.want, got)
		})
	}
}

func TestNoteDetails_Deserialize(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    credit.NoteDetails
		wantErr bool
	}{
		{
			name: "Valid data",
			data: func() []byte {
				buf := make([]byte, 8)
				binary.BigEndian.PutUint64(buf, uint64(12345)<<32|uint64(100))
				return buf
			}(),
			want:    credit.NoteDetails{ID: 12345, Value: 100},
			wantErr: false,
		},
		{
			name:    "Zero values",
			data:    make([]byte, 8),
			want:    credit.NoteDetails{ID: 0, Value: 0},
			wantErr: false,
		},
		{
			name:    "Invalid data length",
			data:    []byte{1, 2, 3},
			want:    credit.NoteDetails{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got credit.NoteDetails
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

func TestNewNoteDetails(t *testing.T) {
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
			got, err := credit.New(tt.value)
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
		idSet := make(map[uint32]bool)
		for i := 0; i < 1000; i++ {
			note, err := credit.New(100)
			require.NoError(t, err)
			require.False(t, idSet[note.ID], "Generated duplicate ID: %v", note.ID)
			idSet[note.ID] = true
		}
	})
}

func TestNote_SerializeDeserialize(t *testing.T) {
	tests := []struct {
		name string
		note credit.Note
	}{
		{
			name: "Valid note",
			note: credit.Note{
				Details:   &credit.NoteDetails{ID: 12345, Value: 100},
				Signature: []byte("test signature"),
			},
		},
		{
			name: "Note with empty signature",
			note: credit.Note{
				Details:   &credit.NoteDetails{ID: 67890, Value: 200},
				Signature: []byte{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serialized := tt.note.Serialize()

			var deserialized credit.Note
			err := deserialized.Deserialize(serialized)
			require.NoError(t, err)
			require.Equal(t, tt.note.Details, deserialized.Details)
			require.Equal(t, tt.note.Signature, deserialized.Signature)
		})
	}
}

func TestNote_StringFromString(t *testing.T) {
	tests := []struct {
		name      string
		note      credit.Note
		wantError bool
	}{
		{
			name: "Valid note",
			note: credit.Note{
				Details:   &credit.NoteDetails{ID: 12345, Value: 100},
				Signature: []byte("test signature"),
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			str := tt.note.String()

			deserialized, err := credit.NewFromString(str)
			require.NoError(t, err)
			require.Equal(t, tt.note.Details, deserialized.Details)
			require.Equal(t, tt.note.Signature, deserialized.Signature)
		})
	}
}

func TestNoteDetails_ToNote(t *testing.T) {
	tests := []struct {
		name      string
		details   credit.NoteDetails
		signature []byte
	}{
		{
			name:      "Valid note details and signature",
			details:   credit.NoteDetails{ID: 12345, Value: 100},
			signature: []byte("test signature"),
		},
		{
			name:      "Valid note details with empty signature",
			details:   credit.NoteDetails{ID: 67890, Value: 200},
			signature: []byte{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			note := tt.details.ToNote(tt.signature)
			require.NotNil(t, note)
			require.Equal(t, tt.details, *note.Details)
			require.Equal(t, tt.signature, note.Signature)
		})
	}
}

func TestNoteDetails_Hash(t *testing.T) {
	tests := []struct {
		name    string
		details credit.NoteDetails
	}{
		{
			name:    "Valid note details",
			details: credit.NoteDetails{ID: 12345, Value: 100},
		},
		{
			name:    "Zero values",
			details: credit.NoteDetails{ID: 0, Value: 0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := tt.details.Hash()
			require.Len(t, hash, 32)

			// Verify that the hash is deterministic
			hash2 := tt.details.Hash()
			require.Equal(t, hash, hash2)

			// Verify that different details produce different hashes
			differentDetails := credit.NoteDetails{ID: tt.details.ID + 1, Value: tt.details.Value}
			differentHash := differentDetails.Hash()
			require.NotEqual(t, hash, differentHash)
		})
	}
}
