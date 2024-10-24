package credit

import (
	"bytes"
	"encoding/binary"
	"math"
	"testing"
)

func TestNoteDetails_Serialize(t *testing.T) {
	tests := []struct {
		name string
		note NoteDetails
		want []byte
	}{
		{
			name: "Valid note",
			note: NoteDetails{ID: 12345, Value: 100},
			want: func() []byte {
				buf := make([]byte, 8)
				binary.BigEndian.PutUint64(buf, uint64(12345)<<32|uint64(100))
				return buf
			}(),
		},
		{
			name: "Zero values",
			note: NoteDetails{ID: 0, Value: 0},
			want: make([]byte, 8),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.note.Serialize()
			if !bytes.Equal(got, tt.want) {
				t.Errorf("NoteDetails.Serialize() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNoteDetails_Deserialize(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    NoteDetails
		wantErr bool
	}{
		{
			name: "Valid data",
			data: func() []byte {
				buf := make([]byte, 8)
				binary.BigEndian.PutUint64(buf, uint64(12345)<<32|uint64(100))
				return buf
			}(),
			want:    NoteDetails{ID: 12345, Value: 100},
			wantErr: false,
		},
		{
			name:    "Zero values",
			data:    make([]byte, 8),
			want:    NoteDetails{ID: 0, Value: 0},
			wantErr: false,
		},
		{
			name:    "Invalid data length",
			data:    []byte{1, 2, 3},
			want:    NoteDetails{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got NoteDetails
			err := got.Deserialize(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("NoteDetails.Deserialize() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("NoteDetails.Deserialize() = %v, want %v", got, tt.want)
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
			got, err := New(tt.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewNoteDetails() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got == nil {
				t.Errorf("NewNoteDetails() returned nil")
				return
			}
			if got.Value != tt.value {
				t.Errorf("NewNoteDetails() Value = %v, want %v", got.Value, tt.value)
			}
			if got.ID == 0 {
				t.Errorf("NewNoteDetails() ID is zero, expected non-zero random value")
			}
		})
	}

	// Test for uniqueness of IDs
	t.Run("Unique IDs", func(t *testing.T) {
		idSet := make(map[uint32]bool)
		for i := 0; i < 1000; i++ {
			note, err := New(100)
			if err != nil {
				t.Errorf("NewNoteDetails() unexpected error: %v", err)
				return
			}
			if idSet[note.ID] {
				t.Errorf("NewNoteDetails() generated duplicate ID: %v", note.ID)
				return
			}
			idSet[note.ID] = true
		}
	})
}

func TestNote_SerializeDeserialize(t *testing.T) {
	tests := []struct {
		name string
		note Note
	}{
		{
			name: "Valid note",
			note: Note{
				Details:   &NoteDetails{ID: 12345, Value: 100},
				Signature: []byte("test signature"),
			},
		},
		{
			name: "Note with empty signature",
			note: Note{
				Details:   &NoteDetails{ID: 67890, Value: 200},
				Signature: []byte{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serialized := tt.note.Serialize()

			var deserialized Note
			err := deserialized.Deserialize(serialized)
			if err != nil {
				t.Errorf("Note.Deserialize() error = %v", err)
				return
			}

			if deserialized.Details.ID != tt.note.Details.ID || deserialized.Details.Value != tt.note.Details.Value {
				t.Errorf("Deserialized NoteDetails do not match original. Got %+v, want %+v", deserialized.Details, tt.note.Details)
			}

			if !bytes.Equal(deserialized.Signature, tt.note.Signature) {
				t.Errorf("Deserialized Signature does not match original. Got %v, want %v", deserialized.Signature, tt.note.Signature)
			}
		})
	}
}

func TestNote_StringFromString(t *testing.T) {
	tests := []struct {
		name      string
		note      Note
		wantError bool
	}{
		{
			name: "Valid note",
			note: Note{
				Details:   &NoteDetails{ID: 12345, Value: 100},
				Signature: []byte("test signature"),
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			str := tt.note.String()

			var deserialized Note
			err := deserialized.FromString(str)
			if err != nil {
				t.Errorf("Note.FromString() error = %v", err)
				return
			}

			if deserialized.Details.ID != tt.note.Details.ID || deserialized.Details.Value != tt.note.Details.Value {
				t.Errorf("Deserialized NoteDetails do not match original. Got %+v, want %+v", deserialized.Details, tt.note.Details)
			}

			if !bytes.Equal(deserialized.Signature, tt.note.Signature) {
				t.Errorf("Deserialized Signature does not match original. Got %v, want %v", deserialized.Signature, tt.note.Signature)
			}
		})
	}
}

func TestNoteDetails_ToNote(t *testing.T) {
	tests := []struct {
		name      string
		details   NoteDetails
		signature []byte
	}{
		{
			name:      "Valid note details and signature",
			details:   NoteDetails{ID: 12345, Value: 100},
			signature: []byte("test signature"),
		},
		{
			name:      "Valid note details with empty signature",
			details:   NoteDetails{ID: 67890, Value: 200},
			signature: []byte{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			note := tt.details.ToNote(tt.signature)

			if note == nil {
				t.Errorf("NoteDetails.ToNote() returned nil")
				return
			}

			if note.Details.ID != tt.details.ID || note.Details.Value != tt.details.Value {
				t.Errorf("Note Details do not match original. Got %+v, want %+v", note.Details, tt.details)
			}

			if !bytes.Equal(note.Signature, tt.signature) {
				t.Errorf("Note Signature does not match input. Got %v, want %v", note.Signature, tt.signature)
			}
		})
	}
}

func TestNoteDetails_Hash(t *testing.T) {
	tests := []struct {
		name    string
		details NoteDetails
	}{
		{
			name:    "Valid note details",
			details: NoteDetails{ID: 12345, Value: 100},
		},
		{
			name:    "Zero values",
			details: NoteDetails{ID: 0, Value: 0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := tt.details.Hash()
			if len(hash) != 32 {
				t.Errorf("NoteDetails.Hash() returned hash of length %d, want 32", len(hash))
			}

			// Verify that the hash is deterministic
			hash2 := tt.details.Hash()
			if !bytes.Equal(hash, hash2) {
				t.Errorf("NoteDetails.Hash() is not deterministic")
			}

			// Verify that different details produce different hashes
			differentDetails := NoteDetails{ID: tt.details.ID + 1, Value: tt.details.Value}
			differentHash := differentDetails.Hash()
			if bytes.Equal(hash, differentHash) {
				t.Errorf("NoteDetails.Hash() produced same hash for different details")
			}
		})
	}
}
