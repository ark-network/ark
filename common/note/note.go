package note

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/btcutil/base58"
)

const noteHRP = "arknote"

// Note represents a note signed by the issuer
type Note struct {
	Data
	Signature []byte
}

// Data contains the data of a note
type Data struct {
	ID    uint64
	Value uint32
}

// New generate a new note data struct with a random ID and the given value
// it must be signed by the issuer and then converted to a Note using Data.ToNote(signature)
func New(value uint32) (*Data, error) {
	randomBytes := make([]byte, 8)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random ID: %w", err)
	}

	id := binary.BigEndian.Uint64(randomBytes)

	return &Data{
		ID:    id,
		Value: value,
	}, nil
}

// NewFromString converts a base58 encoded string with HRP to a Note
func NewFromString(s string) (*Note, error) {
	if !strings.HasPrefix(s, noteHRP) {
		return nil, fmt.Errorf("invalid human-readable part: expected %s prefix (note '%s')", noteHRP, s)
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

// Serialize converts Data to a byte slice
func (n *Data) Serialize() []byte {
	buf := make([]byte, 12)
	binary.BigEndian.PutUint64(buf[:8], n.ID)
	binary.BigEndian.PutUint32(buf[8:], n.Value)
	return buf
}

// Deserialize converts a byte slice to Data
func (n *Data) Deserialize(data []byte) error {
	if len(data) != 12 {
		return fmt.Errorf("invalid data length: expected 12 bytes, got %d", len(data))
	}

	n.ID = binary.BigEndian.Uint64(data[:8])
	n.Value = binary.BigEndian.Uint32(data[8:])
	return nil
}

// Hash returns the SHA256 hash of the serialized Data
func (n *Data) Hash() []byte {
	hash := sha256.Sum256(n.Serialize())
	return hash[:]
}

// Serialize converts the Note to a byte slice
func (n *Note) Serialize() []byte {
	detailsBytes := n.Data.Serialize()
	return append(detailsBytes, n.Signature...)
}

// Deserialize converts a byte slice to a Note
func (n *Note) Deserialize(data []byte) error {
	if len(data) < 12 {
		return fmt.Errorf("invalid data length: expected at least 12 bytes, got %d", len(data))
	}

	dataCopy := &Data{}
	if err := dataCopy.Deserialize(data[:12]); err != nil {
		return err
	}

	n.Data = *dataCopy

	if len(data) > 12 {
		n.Signature = data[13:]
	}

	return nil
}

// String converts the Note to a base58 encoded string with HRP
func (n Note) String() string {
	return noteHRP + base58.Encode(n.Serialize())
}

// ToNote creates a Note from Data with the given signature
func (n *Data) ToNote(signature []byte) *Note {
	return &Note{
		Data:      *n,
		Signature: signature,
	}
}
