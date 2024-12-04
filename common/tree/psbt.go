package tree

import (
	"bytes"

	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
	"github.com/vulpemventures/go-elements/psetv2"
)

var (
	CONDITION_WITNESS_KEY_PREFIX = []byte(ConditionWitnessKey)
)

func AddConditionWitness(inIndex int, ptx *psetv2.Pset, witness wire.TxWitness) error {
	var witnessBytes bytes.Buffer

	err := psbt.WriteTxWitness(&witnessBytes, witness)
	if err != nil {
		return err
	}

	ptx.Inputs[inIndex].Unknowns = append(ptx.Inputs[inIndex].Unknowns, psetv2.KeyPair{
		Key:   psetv2.Key{KeyData: CONDITION_WITNESS_KEY_PREFIX, KeyType: uint8(0)},
		Value: witnessBytes.Bytes(),
	})
	return nil
}

func GetConditionWitness(in psetv2.Input) (wire.TxWitness, error) {
	for _, u := range in.Unknowns {
		if bytes.HasPrefix(u.Key.KeyData, CONDITION_WITNESS_KEY_PREFIX) {
			return ReadTxWitness(u.Value)
		}
	}

	return wire.TxWitness{}, nil
}
