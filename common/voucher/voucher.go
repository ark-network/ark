package voucher

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/btcutil/base58"
)

const voucherHRP = "anote"

// Voucher represents a voucher signed by the issuer
type Voucher struct {
	Data
	Signature []byte
}

// Data contains the data of a voucher
type Data struct {
	ID    uint64
	Value uint32
}

// New generate a new voucher data struct with a random ID and the given value
// it must be signed by the issuer and then converted to a Voucher using Data.ToVoucher(signature)
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

// NewFromString converts a base58 encoded string with HRP to a Voucher
func NewFromString(s string) (*Voucher, error) {
	if !strings.HasPrefix(s, voucherHRP) {
		return nil, fmt.Errorf("invalid human-readable part: expected %s prefix (voucher '%s')", voucherHRP, s)
	}

	encoded := strings.TrimPrefix(s, voucherHRP)
	decoded := base58.Decode(encoded)
	if len(decoded) == 0 {
		return nil, fmt.Errorf("failed to decode base58 string")
	}

	voucher := &Voucher{}
	err := voucher.Deserialize(decoded)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize voucher: %w", err)
	}

	return voucher, nil
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

// Serialize converts the Voucher to a byte slice
func (n *Voucher) Serialize() []byte {
	detailsBytes := n.Data.Serialize()
	sigLen := len(n.Signature)

	buf := make([]byte, 12+1+sigLen)
	copy(buf, detailsBytes)
	buf[12] = byte(sigLen)
	copy(buf[13:], n.Signature)

	return buf
}

// Deserialize converts a byte slice to a Voucher
func (n *Voucher) Deserialize(data []byte) error {
	if len(data) < 13 {
		return fmt.Errorf("invalid data length: expected at least 13 bytes, got %d", len(data))
	}

	dataCopy := &Data{}
	if err := dataCopy.Deserialize(data[:12]); err != nil {
		return err
	}

	n.Data = *dataCopy

	sigLen := int(data[12])
	if len(data) != 13+sigLen {
		return fmt.Errorf("invalid data length: expected %d bytes, got %d", 13+sigLen, len(data))
	}

	n.Signature = make([]byte, sigLen)
	copy(n.Signature, data[13:])

	return nil
}

// String converts the Note to a base58 encoded string with HRP
func (n Voucher) String() string {
	return voucherHRP + base58.Encode(n.Serialize())
}

// ToVoucher creates a Voucher from Data with the given signature
func (n *Data) ToVoucher(signature []byte) *Voucher {
	return &Voucher{
		Data:      *n,
		Signature: signature,
	}
}
