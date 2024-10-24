package credit

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/btcutil/base58"
)

const noteHRP = "ark"

// Note represents a virtual note signed by the issuer
type Note struct {
	Details   *NoteDetails
	Signature []byte
}

// NoteDetails contains the data of a virtual note
type NoteDetails struct {
	ID    uint64
	Value uint32
}

// New creates a new NoteDetails with the given value and a random ID
func New(value uint32) (*NoteDetails, error) {
	randomBytes := make([]byte, 8)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random ID: %w", err)
	}

	id := binary.BigEndian.Uint64(randomBytes)

	return &NoteDetails{
		ID:    id,
		Value: value,
	}, nil
}

// NewFromString converts a base58 encoded string with HRP to a Note
func NewFromString(s string) (*Note, error) {
	if !strings.HasPrefix(s, noteHRP) {
		return nil, fmt.Errorf("invalid human-readable part: expected %s prefix", noteHRP)
	}

	encoded := strings.TrimPrefix(s, noteHRP)
	decoded := base58.Decode(encoded)
	if len(decoded) == 0 {
		return nil, fmt.Errorf("failed to decode base58 string")
	}

	note := &Note{}
	err := note.Deserialize(decoded)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize note: %w", err)
	}

	return note, nil
}

// Serialize converts the NoteDetails to a byte slice
func (n *NoteDetails) Serialize() []byte {
	buf := make([]byte, 12)
	binary.BigEndian.PutUint64(buf[:8], n.ID)
	binary.BigEndian.PutUint32(buf[8:], n.Value)
	return buf
}

// Deserialize converts a byte slice to a NoteDetails
func (n *NoteDetails) Deserialize(data []byte) error {
	if len(data) != 12 {
		return fmt.Errorf("invalid data length: expected 12 bytes, got %d", len(data))
	}

	n.ID = binary.BigEndian.Uint64(data[:8])
	n.Value = binary.BigEndian.Uint32(data[8:])
	return nil
}

// Hash returns the SHA256 hash of the serialized NoteDetails
func (n *NoteDetails) Hash() []byte {
	hash := sha256.Sum256(n.Serialize())
	return hash[:]
}

// Serialize converts the Note to a byte slice
func (n *Note) Serialize() []byte {
	detailsBytes := n.Details.Serialize()
	sigLen := len(n.Signature)

	buf := make([]byte, 12+1+sigLen)
	copy(buf, detailsBytes)
	buf[12] = byte(sigLen)
	copy(buf[13:], n.Signature)

	return buf
}

// Deserialize converts a byte slice to a Note
func (n *Note) Deserialize(data []byte) error {
	if len(data) < 13 {
		return fmt.Errorf("invalid data length: expected at least 13 bytes, got %d", len(data))
	}

	n.Details = &NoteDetails{}
	if err := n.Details.Deserialize(data[:12]); err != nil {
		return err
	}

	sigLen := int(data[12])
	if len(data) != 13+sigLen {
		return fmt.Errorf("invalid data length: expected %d bytes, got %d", 13+sigLen, len(data))
	}

	n.Signature = make([]byte, sigLen)
	copy(n.Signature, data[13:])

	return nil
}

// String converts the Note to a base58 encoded string with HRP
func (n Note) String() string {
	return noteHRP + base58.Encode(n.Serialize())
}

// ToNote creates a Note from NoteDetails with the given signature
func (n *NoteDetails) ToNote(signature []byte) *Note {
	return &Note{
		Details:   n,
		Signature: signature,
	}
}
