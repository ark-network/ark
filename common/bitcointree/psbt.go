package bitcointree

import (
	"bytes"

	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

var (
	COSIGNER_PSBT_KEY_PREFIX = []byte("cosigner")
)

// P2A script = p2wsh(OP_TRUE)
var ANCHOR_PKSCRIPT = []byte{0, 32, 74, 232, 21, 114, 240, 110, 27, 136, 253, 92, 237, 122, 26, 0, 9, 69, 67, 46, 131, 225, 85, 30, 111, 114, 30, 233, 192, 11, 140, 195, 50, 96}
var ANCHOR_AMOUNT = int64(330) // dust amount for P2A

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
		cosignerIndex := parsePrefixedCosignerKey(u.Key)
		if cosignerIndex == -1 {
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
	return append(COSIGNER_PSBT_KEY_PREFIX, byte(index))
}

func parsePrefixedCosignerKey(key []byte) int {
	if !bytes.HasPrefix(key, COSIGNER_PSBT_KEY_PREFIX) {
		return -1
	}

	return int(key[len(COSIGNER_PSBT_KEY_PREFIX)])
}
