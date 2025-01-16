package bitcointree

import (
	"bytes"
	"encoding/binary"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/tree"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

var (
	COSIGNER_PSBT_KEY_PREFIX     = []byte("cosigner")
	CONDITION_WITNESS_KEY_PREFIX = []byte(tree.ConditionWitnessKey)
	LIFETIME_PSBT_KEY            = []byte("lifetime")
)

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

func AddLifetime(inIndex int, ptx *psbt.Packet, lifetime common.RelativeLocktime) error {
	ptx.Inputs[inIndex].Unknowns = append(ptx.Inputs[inIndex].Unknowns, &psbt.Unknown{
		Value: lifetime.Bytes(),
		Key:   LIFETIME_PSBT_KEY,
	})

	return nil
}

func GetLifetime(in psbt.PInput) (*common.RelativeLocktime, error) {
	for _, u := range in.Unknowns {
		if bytes.Contains(u.Key, LIFETIME_PSBT_KEY) {
			return common.NewRelativeLocktimeFromBytes(u.Value)
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
