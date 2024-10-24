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
	ID    uint32
	Value uint32
}

// New creates a new NoteDetails with the given value and a random ID
func New(value uint32) (*NoteDetails, error) {
	randomBytes := make([]byte, 4)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random ID: %w", err)
	}

	return &NoteDetails{
		ID:    binary.BigEndian.Uint32(randomBytes),
		Value: value,
	}, nil
}

// Serialize converts the NoteDetails to a byte slice
func (n *NoteDetails) Serialize() []byte {
	combined := uint64(n.ID)<<32 | uint64(n.Value)
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, combined)
	return buf
}

// Deserialize converts a byte slice to a NoteDetails
func (n *NoteDetails) Deserialize(data []byte) error {
	if len(data) != 8 {
		return fmt.Errorf("invalid data length: expected 8 bytes, got %d", len(data))
	}

	combined := binary.BigEndian.Uint64(data)
	n.ID = uint32(combined >> 32)
	n.Value = uint32(combined & 0xFFFFFFFF)
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

	buf := make([]byte, 8+1+sigLen)
	copy(buf, detailsBytes)
	buf[8] = byte(sigLen)
	copy(buf[9:], n.Signature)

	return buf
}

// Deserialize converts a byte slice to a Note
func (n *Note) Deserialize(data []byte) error {
	if len(data) < 9 {
		return fmt.Errorf("invalid data length: expected at least 9 bytes, got %d", len(data))
	}

	n.Details = &NoteDetails{}
	if err := n.Details.Deserialize(data[:8]); err != nil {
		return err
	}

	sigLen := int(data[8])
	if len(data) != 9+sigLen {
		return fmt.Errorf("invalid data length: expected %d bytes, got %d", 9+sigLen, len(data))
	}

	n.Signature = make([]byte, sigLen)
	copy(n.Signature, data[9:])

	return nil
}

// String converts the Note to a base58 encoded string with HRP
func (n Note) String() string {
	return noteHRP + base58.Encode(n.Serialize())
}

// FromString converts a base58 encoded string with HRP to a Note
func (n *Note) FromString(s string) error {
	if !strings.HasPrefix(s, noteHRP) {
		return fmt.Errorf("invalid human-readable part: expected %s prefix", noteHRP)
	}

	encoded := strings.TrimPrefix(s, noteHRP)
	decoded := base58.Decode(encoded)
	if len(decoded) == 0 {
		return fmt.Errorf("failed to decode base58 string")
	}

	return n.Deserialize(decoded)
}

// ToNote creates a Note from NoteDetails with the given signature
func (n *NoteDetails) ToNote(signature []byte) *Note {
	return &Note{
		Details:   n,
		Signature: signature,
	}
}
