package bufferutil

import (
	"bytes"
	"encoding/binary"
	"math"
	"reflect"
	"testing"
)

func TestSerializerAndDeserializer(t *testing.T) {
	t.Run("WriteReadUint8", testWriteReadUint8)
	t.Run("WriteReadUint32", testWriteReadUint32)
	t.Run("WriteReadUint64", testWriteReadUint64)
	t.Run("WriteReadVarInt", testWriteReadVarInt)
	t.Run("WriteReadSlice", testWriteReadSlice)
	t.Run("WriteReadVarSlice", testWriteReadVarSlice)
	t.Run("WriteReadVector", testWriteReadVector)
}

func testWriteReadUint8(t *testing.T) {
	buf := bytes.NewBuffer([]byte{})
	bw := NewSerializer(buf)

	tests := struct {
		in       []uint8
		expected []byte
	}{
		[]uint8{0, 1, 254, 255},
		[]byte{0x00, 0x01, 0xfe, 0xff},
	}

	for _, v := range tests.in {
		err := bw.WriteUint8(v)
		if err != nil {
			t.Fatal(err)
		}
	}

	br := NewDeserializer(bw.buffer)
	for _, expected := range tests.expected {
		res, err := br.ReadUint8()
		if err != nil {
			t.Fatal(err)
		}
		if res != expected {
			t.Fatalf("Got: %d, expected: %d", res, expected)
		}
	}
}

func testWriteReadUint32(t *testing.T) {
	buf := bytes.NewBuffer([]byte{})
	bw := NewSerializer(buf)

	tests := struct {
		in       []uint32
		expected [][]byte
	}{
		[]uint32{
			0,
			1,
			uint32(math.Pow(2, 16)),
			uint32(math.Pow(2, 32) - 1),
		},
		[][]byte{
			[]byte{0x00, 0x00, 0x00, 0x00},
			[]byte{0x01, 0x00, 0x00, 0x00},
			[]byte{0x00, 0x00, 0x01, 0x00},
			[]byte{0xff, 0xff, 0xff, 0xff},
		},
	}

	for _, v := range tests.in {
		err := bw.WriteUint32(v)
		if err != nil {
			t.Fatal(err)
		}
	}

	br := NewDeserializer(bw.buffer)
	for _, expected := range tests.expected {
		res, err := br.ReadUint32()
		if err != nil {
			t.Fatal(err)
		}
		if exp := binary.LittleEndian.Uint32(expected); res != exp {
			t.Fatalf("Got: %d, expected: %d", res, exp)
		}
	}
}

func testWriteReadUint64(t *testing.T) {
	buf := bytes.NewBuffer([]byte{})
	bw := NewSerializer(buf)

	tests := struct {
		in       []uint64
		expected [][]byte
	}{
		[]uint64{
			0,
			1,
			uint64(math.Pow(2, 32)),
			uint64(math.Pow(2, 53) - 1),
		},
		[][]byte{
			[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			[]byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			[]byte{0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00},
			[]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x1f, 0x00},
		},
	}

	for _, v := range tests.in {
		err := bw.WriteUint64(v)
		if err != nil {
			t.Fatal(err)
		}
	}

	br := NewDeserializer(bw.buffer)
	for _, expected := range tests.expected {
		res, err := br.ReadUint64()
		if err != nil {
			t.Fatal(err)
		}
		if exp := binary.LittleEndian.Uint64(expected); res != exp {
			t.Fatalf("Got: %d, expected: %d", res, exp)
		}
	}
}

func testWriteReadVarInt(t *testing.T) {
	buf := bytes.NewBuffer([]byte{})
	bw := NewSerializer(buf)

	tests := struct {
		in       []uint64
		expected [][]byte
	}{
		[]uint64{
			0,
			1,
			252,
			253,
			254,
			255,
			256,
			uint64(math.Pow(2, 16) - 2),
			uint64(math.Pow(2, 16) - 1),
			uint64(math.Pow(2, 16)),
			uint64(math.Pow(2, 32) - 2),
			uint64(math.Pow(2, 32) - 1),
			uint64(math.Pow(2, 32)),
			uint64(math.Pow(2, 53) - 1),
		},
		[][]byte{
			[]byte{0x00},
			[]byte{0x01},
			[]byte{0xfc},
			[]byte{0xfd, 0xfd, 0x00},
			[]byte{0xfd, 0xfe, 0x00},
			[]byte{0xfd, 0xff, 0x00},
			[]byte{0xfd, 0x00, 0x01},
			[]byte{0xfd, 0xfe, 0xff},
			[]byte{0xfd, 0xff, 0xff},
			[]byte{0xfe, 0x00, 0x00, 0x01, 0x00},
			[]byte{0xfe, 0xfe, 0xff, 0xff, 0xff},
			[]byte{0xfe, 0xff, 0xff, 0xff, 0xff},
			[]byte{0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00},
			[]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x1f, 0x00},
		},
	}

	for _, v := range tests.in {
		err := bw.WriteVarInt(v)
		if err != nil {
			t.Fatal(err)
		}
	}

	br := NewDeserializer(bw.buffer)
	for _, expected := range tests.expected {
		res, err := br.ReadVarInt()
		if err != nil {
			t.Fatal(err)
		}
		if exp, _ := readVarInt(bytes.NewBuffer(expected)); res != exp {
			t.Fatalf("Got: %d, expected: %d", res, exp)
		}
	}
}

func testWriteReadSlice(t *testing.T) {
	buf := bytes.NewBuffer([]byte{})
	bw := NewSerializer(buf)

	tests := struct {
		in [][]byte
	}{
		[][]byte{
			[]byte{},
			[]byte{1},
			[]byte{1, 2, 3, 4},
			[]byte{254, 255},
		},
	}

	for _, v := range tests.in {
		err := bw.WriteSlice(v)
		if err != nil {
			t.Fatal(err)
		}
	}

	br := NewDeserializer(bw.buffer)
	for _, v := range tests.in {
		res, err := br.ReadSlice(uint(len(v)))
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(res, v) {
			t.Fatalf("Got: %b, expected: %b", res, v)
		}
	}
}

func testWriteReadVarSlice(t *testing.T) {
	buf := bytes.NewBuffer([]byte{})
	bw := NewSerializer(buf)

	t1 := filledSlice(252, 2)
	t2 := filledSlice(253, 3)
	tests := struct {
		in       [][]byte
		expected [][]byte
	}{
		[][]byte{
			[]byte{0x01},
			t1,
			t2,
		},
		[][]byte{
			[]byte{0x01, 0x01},
			append([]byte{0xfc}, t1...),
			append([]byte{0xfd, 0xfd, 0x00}, t2...),
		},
	}

	for _, v := range tests.in {
		err := bw.WriteVarSlice(v)
		if err != nil {
			t.Fatal(err)
		}
	}

	br := NewDeserializer(bw.buffer)
	for _, v := range tests.in {
		res, err := br.ReadVarSlice()
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(res, v) {
			t.Fatalf("Got: %b, expected: %b", res, v)
		}
	}
}

func testWriteReadVector(t *testing.T) {
	buf := bytes.NewBuffer([]byte{})
	bw := NewSerializer(buf)

	t1 := filledSlice(253, 5)
	t2 := filledSliceArray(253, []byte{6})

	tests := struct {
		in [][][]byte
	}{
		[][][]byte{
			[][]byte{
				[]byte{0x04},
				t1,
			},
			t2,
		},
	}

	for _, v := range tests.in {
		err := bw.WriteVector(v)
		if err != nil {
			t.Fatal(err)
		}
	}

	br := NewDeserializer(bw.buffer)
	for _, v := range tests.in {
		res, err := br.ReadVector()
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(res, v) {
			t.Fatalf("Got: %b, expected: %b", res, v)
		}
	}
}

func filledSlice(n int, val uint8) []byte {
	v := make([]byte, n)
	for i := range v {
		v[i] = val
	}
	return v
}

func filledSliceArray(n int, val []byte) [][]byte {
	v := make([][]byte, n)
	for i := range v {
		v[i] = make([]byte, len(val))
		copy(v[i], val)
	}
	return v
}
