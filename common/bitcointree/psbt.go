package bitcointree

import (
	"bytes"

	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

var (
	COSIGNER_PSBT_KEY_PREFIX = []byte("cosigner")
)

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
