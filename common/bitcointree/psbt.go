package bitcointree

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/tree"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

var (
	COSIGNER_PSBT_KEY_PREFIX     = []byte("cosigner")
	CONDITION_WITNESS_KEY_PREFIX = []byte(tree.ConditionWitnessKey)
	VTXO_TREE_EXPIRY_PSBT_KEY    = []byte("expiry")
	VTXO_TAPROOT_TREE_KEY        = []byte("taptree")
)

// AddTaprootTree adds the whole taproot tree of the VTXO to the given PSBT input.
// it follows the format of PSBT_OUT_TAP_TREE / BIP-371
func AddTaprootTree(inIndex int, ptx *psbt.Packet, leaves []string) error {
	var tapscriptsBytes bytes.Buffer

	// write number of leaves as compact size uint
	if err := writeCompactSizeUint(&tapscriptsBytes, uint64(len(leaves))); err != nil {
		return err
	}

	for _, tapscript := range leaves {
		scriptBytes, err := hex.DecodeString(tapscript)
		if err != nil {
			return err
		}

		// write depth (always 1)
		// TODO: allow multiple depth
		if err := tapscriptsBytes.WriteByte(1); err != nil {
			return err
		}

		if err := tapscriptsBytes.WriteByte(byte(txscript.BaseLeafVersion)); err != nil {
			return err
		}

		// write script
		if err := writeCompactSizeUint(&tapscriptsBytes, uint64(len(scriptBytes))); err != nil {
			return err
		}
		if _, err := tapscriptsBytes.Write(scriptBytes); err != nil {
			return err
		}
	}

	ptx.Inputs[inIndex].Unknowns = append(ptx.Inputs[inIndex].Unknowns, &psbt.Unknown{
		Value: tapscriptsBytes.Bytes(),
		Key:   VTXO_TAPROOT_TREE_KEY,
	})
	return nil
}

// GetTaprootTree returns the taproot tree of the given PSBT input.
func GetTaprootTree(in psbt.PInput) ([]string, error) {
	var leaves []string

	for _, u := range in.Unknowns {
		if bytes.Equal(u.Key, VTXO_TAPROOT_TREE_KEY) {
			buf := bytes.NewReader(u.Value)

			// len of tapscripts
			count, err := readCompactSizeUint(buf)
			if err != nil {
				return nil, err
			}

			for i := uint64(0); i < count; i++ {
				// depth : ignore
				if _, err := buf.ReadByte(); err != nil {
					return nil, err
				}

				// leaf version : ignore, we assume base tapscript
				if _, err := buf.ReadByte(); err != nil {
					return nil, err
				}

				// script length
				scriptLen, err := readCompactSizeUint(buf)
				if err != nil {
					return nil, err
				}

				// script bytes
				scriptBytes := make([]byte, scriptLen)
				if _, err := buf.Read(scriptBytes); err != nil {
					return nil, err
				}

				leaves = append(leaves, hex.EncodeToString(scriptBytes))
			}
			break
		}
	}

	return leaves, nil
}

func AddConditionWitness(inIndex int, ptx *psbt.Packet, witness wire.TxWitness) error {
	var witnessBytes bytes.Buffer

	err := psbt.WriteTxWitness(&witnessBytes, witness)
	if err != nil {
		return err
	}

	ptx.Inputs[inIndex].Unknowns = append(ptx.Inputs[inIndex].Unknowns, &psbt.Unknown{
		Value: witnessBytes.Bytes(),
		Key:   CONDITION_WITNESS_KEY_PREFIX,
	})
	return nil
}

func GetConditionWitness(in psbt.PInput) (wire.TxWitness, error) {
	for _, u := range in.Unknowns {
		if bytes.Contains(u.Key, CONDITION_WITNESS_KEY_PREFIX) {
			return tree.ReadTxWitness(u.Value)
		}
	}

	return wire.TxWitness{}, nil
}

func AddVtxoTreeExpiry(inIndex int, ptx *psbt.Packet, vtxoTreeExpiry common.RelativeLocktime) error {
	sequence, err := common.BIP68Sequence(vtxoTreeExpiry)
	if err != nil {
		return err
	}

	// the sequence must be encoded as minimal little-endian bytes
	var sequenceLE [4]byte
	binary.LittleEndian.PutUint32(sequenceLE[:], sequence)

	// compute the minimum number of bytes needed
	numBytes := 4
	for numBytes > 1 && sequenceLE[numBytes-1] == 0 {
		numBytes-- // remove trailing zeros
	}

	// if the most significant bit of the last byte is set,
	// we need one more byte to avoid sign ambiguity
	if sequenceLE[numBytes-1]&0x80 != 0 {
		numBytes++
	}

	ptx.Inputs[inIndex].Unknowns = append(ptx.Inputs[inIndex].Unknowns, &psbt.Unknown{
		Value: sequenceLE[:numBytes],
		Key:   VTXO_TREE_EXPIRY_PSBT_KEY,
	})

	return nil
}

func GetVtxoTreeExpiry(in psbt.PInput) (*common.RelativeLocktime, error) {
	for _, u := range in.Unknowns {
		if bytes.Contains(u.Key, VTXO_TREE_EXPIRY_PSBT_KEY) {
			return common.BIP68DecodeSequence(u.Value)
		}
	}

	return nil, nil
}

func AddCosignerKey(inIndex int, ptx *psbt.Packet, key *secp256k1.PublicKey) error {
	currentCosigners, err := GetCosignerKeys(ptx.Inputs[inIndex])
	if err != nil {
		return err
	}

	nextCosignerIndex := len(currentCosigners)

	ptx.Inputs[inIndex].Unknowns = append(ptx.Inputs[inIndex].Unknowns, &psbt.Unknown{
		Value: key.SerializeCompressed(),
		Key:   cosignerPrefixedKey(nextCosignerIndex),
	})

	return nil
}

func GetCosignerKeys(in psbt.PInput) ([]*secp256k1.PublicKey, error) {
	var keys []*secp256k1.PublicKey
	for _, u := range in.Unknowns {
		if !parsePrefixedCosignerKey(u.Key) {
			continue
		}

		key, err := secp256k1.ParsePubKey(u.Value)
		if err != nil {
			return nil, err
		}

		keys = append(keys, key)
	}

	return keys, nil
}

func cosignerPrefixedKey(index int) []byte {
	indexBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(indexBytes, uint32(index))

	return append(COSIGNER_PSBT_KEY_PREFIX, indexBytes...)
}

func parsePrefixedCosignerKey(key []byte) bool {
	return bytes.HasPrefix(key, COSIGNER_PSBT_KEY_PREFIX)
}

// readCompactSizeUint reads a compact size uint from the reader
func readCompactSizeUint(r *bytes.Reader) (uint64, error) {
	firstByte, err := r.ReadByte()
	if err != nil {
		return 0, err
	}

	switch firstByte {
	case 253:
		var val uint16
		if err := binary.Read(r, binary.LittleEndian, &val); err != nil {
			return 0, err
		}
		return uint64(val), nil
	case 254:
		var val uint32
		if err := binary.Read(r, binary.LittleEndian, &val); err != nil {
			return 0, err
		}
		return uint64(val), nil
	case 255:
		var val uint64
		if err := binary.Read(r, binary.LittleEndian, &val); err != nil {
			return 0, err
		}
		return val, nil
	default:
		return uint64(firstByte), nil
	}
}

// writeCompactSizeUint writes a compact size uint to the writer
func writeCompactSizeUint(w *bytes.Buffer, val uint64) error {
	if val < 253 {
		return w.WriteByte(byte(val))
	}
	if val < 0x10000 {
		if err := w.WriteByte(253); err != nil {
			return err
		}
		return binary.Write(w, binary.LittleEndian, uint16(val))
	}
	if val < 0x100000000 {
		if err := w.WriteByte(254); err != nil {
			return err
		}
		return binary.Write(w, binary.LittleEndian, uint32(val))
	}
	if err := w.WriteByte(255); err != nil {
		return err
	}
	return binary.Write(w, binary.LittleEndian, val)
}
