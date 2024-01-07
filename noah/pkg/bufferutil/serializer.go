package bufferutil

import (
	"bytes"
)

// Serializer implements methods that help to serialize an Elements transaction.
type Serializer struct {
	buffer *bytes.Buffer
}

// NewSerializer returns an instance of Serializer.
func NewSerializer(buf *bytes.Buffer) *Serializer {
	if buf == nil {
		buf = bytes.NewBuffer([]byte{})
	}
	return &Serializer{buf}
}

// Bytes returns writer's buffer
func (s *Serializer) Bytes() []byte {
	return s.buffer.Bytes()
}

// WriteUint8 writes the given uint8 value to writer's buffer.
func (s *Serializer) WriteUint8(val uint8) error {
	return BinarySerializer.PutUint8(s.buffer, val)
}

// WriteUint16 writes the given uint8 value to writer's buffer.
func (s *Serializer) WriteUint16(val uint16) error {
	return BinarySerializer.PutUint16(s.buffer, littleEndian, val)
}

// WriteUint32 writes the given uint32 value to writer's buffer.
func (s *Serializer) WriteUint32(val uint32) error {
	return BinarySerializer.PutUint32(s.buffer, littleEndian, val)
}

// WriteUint64 writes the given uint64 value to writer's buffer.
func (s *Serializer) WriteUint64(val uint64) error {
	return BinarySerializer.PutUint64(s.buffer, littleEndian, val)
}

// WriteVarInt serializes the given value to writer's buffer
// using a variable number of bytes depending on its value.
func (s *Serializer) WriteVarInt(val uint64) error {
	return writeVarInt(s.buffer, val)
}

// WriteSlice appends the given byte array to the writer's buffer
func (s *Serializer) WriteSlice(val []byte) error {
	_, err := s.buffer.Write(val)
	return err
}

// WriteVarSlice appends the length of the given byte array as var int
// and the byte array itself to the writer's buffer
func (s *Serializer) WriteVarSlice(val []byte) error {
	err := s.WriteVarInt(uint64(len(val)))
	if err != nil {
		return err
	}
	return s.WriteSlice(val)
}

// WriteVector appends an array of array bytes to the writer's buffer
func (s *Serializer) WriteVector(v [][]byte) error {
	err := s.WriteVarInt(uint64(len(v)))
	if err != nil {
		return err
	}
	for _, val := range v {
		err := s.WriteVarSlice(val)
		if err != nil {
			return err
		}
	}
	return nil
}
