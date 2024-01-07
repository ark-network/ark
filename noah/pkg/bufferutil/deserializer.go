package bufferutil

import (
	"bytes"
	"fmt"
)

// Deserializer implements methods that help to deserialize an Elements transaction.
type Deserializer struct {
	buffer *bytes.Buffer
}

// NewDeserializer returns an instance of Deserializer.
func NewDeserializer(buffer *bytes.Buffer) *Deserializer {
	return &Deserializer{buffer}
}

// ReadToEnd returns bytes left in buffer
func (d *Deserializer) ReadToEnd() []byte {
	return d.buffer.Bytes()
}

// ReadUint8 reads a uint8 value from reader's buffer.
func (d *Deserializer) ReadUint8() (uint8, error) {
	return BinarySerializer.Uint8(d.buffer)
}

// ReadUint16 reads a uint16 value from reader's buffer.
func (d *Deserializer) ReadUint16() (uint16, error) {
	return BinarySerializer.Uint16(d.buffer, littleEndian)
}

// ReadUint32 reads a uint32 value from reader's buffer.
func (d *Deserializer) ReadUint32() (uint32, error) {
	return BinarySerializer.Uint32(d.buffer, littleEndian)
}

// ReadUint64 reads a uint64 value from reader's buffer.
func (d *Deserializer) ReadUint64() (uint64, error) {
	return BinarySerializer.Uint64(d.buffer, littleEndian)
}

// ReadVarInt reads a variable length integer from reader's buffer and returns it as a uint64.
func (d *Deserializer) ReadVarInt() (uint64, error) {
	return readVarInt(d.buffer)
}

// ReadSlice reads the next n bytes from the reader's buffer
func (d *Deserializer) ReadSlice(n uint) ([]byte, error) {
	decoded := make([]byte, n)
	_, err := d.buffer.Read(decoded)
	if err != nil {
		return nil, err
	}
	return decoded, nil
}

// ReadVarSlice first reads the length n of the bytes, then reads the next n bytes
func (d *Deserializer) ReadVarSlice() ([]byte, error) {
	n, err := d.ReadVarInt()
	if err != nil {
		return nil, err
	}
	return d.ReadSlice(uint(n))
}

// ReadVector reads the length n of the array of bytes, then reads the next n array bytes
func (d *Deserializer) ReadVector() ([][]byte, error) {
	n, err := d.ReadVarInt()
	if err != nil {
		return nil, err
	}
	v := [][]byte{}
	for i := uint(0); i < uint(n); i++ {
		val, err := d.ReadVarSlice()
		if err != nil {
			return nil, err
		}
		v = append(v, val)
	}
	return v, nil
}

// ReadElementsValue reads the first byte to determine if the value is
// confidential or unconfidential, then reads the right number of bytes accordingly.
func (d *Deserializer) ReadElementsValue() ([]byte, error) {
	version, err := d.ReadUint8()
	if err != nil {
		return nil, err
	}

	// special case: if issuance token amount is not defined it's encoded as 0x00
	if version == 0 {
		return []byte{version}, nil
	}

	buf := []byte{version}
	nextBytes := []byte{}
	if version == 1 {
		nextBytes, err = d.ReadSlice(8)
		if err != nil {
			return nil, err
		}
	}
	if version == 8 || version == 9 {
		nextBytes, err = d.ReadSlice(32)
		if err != nil {
			return nil, err
		}
	}
	if len(nextBytes) == 0 {
		return nil, fmt.Errorf("Invalid prefix %d", version)
	}
	buf = append(buf, nextBytes...)
	return buf, nil
}

// ReadElementsAsset reads an Elements output asset form the reader's buffer
func (d *Deserializer) ReadElementsAsset() ([]byte, error) {
	version, err := d.ReadUint8()
	if err != nil {
		return nil, err
	}

	if version == 1 || version == 10 || version == 11 {
		b, err := d.ReadSlice(32)
		if err != nil {
			return nil, err
		}
		buf := []byte{version}
		buf = append(buf, b...)
		return buf, nil
	}

	return nil, fmt.Errorf("Invalid prefix %d", version)
}

// ReadElementsNonce reads a maybe non-zero Elements output nonce form the reader's buffer
func (d *Deserializer) ReadElementsNonce() ([]byte, error) {
	version, err := d.ReadUint8()
	if err != nil {
		return nil, err
	}

	buf := []byte{version}
	if version >= 1 && version <= 3 {
		b, err := d.ReadSlice(32)
		if err != nil {
			return nil, err
		}
		buf = append(buf, b...)
		return buf, nil
	}

	return buf, nil
}
