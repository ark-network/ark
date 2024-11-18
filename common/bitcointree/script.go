package bitcointree

import (
	"bytes"
	"fmt"

	"github.com/ark-network/ark/common"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type Closure interface {
	Leaf() (*txscript.TapLeaf, error)
	Decode(script []byte) (bool, error)
}

type CSVSigClosure struct {
	Pubkey  *secp256k1.PublicKey
	Seconds uint
}

type MultisigClosure struct {
	Pubkey    *secp256k1.PublicKey
	AspPubkey *secp256k1.PublicKey
}

func DecodeClosure(script []byte) (Closure, error) {
	var closure Closure

	closure = &CSVSigClosure{}
	if valid, err := closure.Decode(script); err == nil && valid {
		return closure, nil
	}

	closure = &MultisigClosure{}
	if valid, err := closure.Decode(script); err == nil && valid {
		return closure, nil
	}

	return nil, fmt.Errorf("invalid closure script")

}

func (f *MultisigClosure) Leaf() (*txscript.TapLeaf, error) {
	aspKeyBytes := schnorr.SerializePubKey(f.AspPubkey)
	userKeyBytes := schnorr.SerializePubKey(f.Pubkey)

	script, err := txscript.NewScriptBuilder().AddData(aspKeyBytes).
		AddOp(txscript.OP_CHECKSIGVERIFY).AddData(userKeyBytes).
		AddOp(txscript.OP_CHECKSIG).Script()
	if err != nil {
		return nil, err
	}

	tapLeaf := txscript.NewBaseTapLeaf(script)
	return &tapLeaf, nil
}

func (f *MultisigClosure) Decode(script []byte) (bool, error) {
	valid, aspPubKey, err := decodeChecksigScript(script)
	if err != nil {
		return false, err
	}

	if !valid {
		return false, nil
	}

	valid, pubkey, err := decodeChecksigScript(script[33:])
	if err != nil {
		return false, err
	}

	if !valid {
		return false, nil
	}

	f.Pubkey = pubkey
	f.AspPubkey = aspPubKey

	rebuilt, err := f.Leaf()
	if err != nil {
		return false, err
	}

	if !bytes.Equal(rebuilt.Script, script) {
		return false, nil
	}

	return true, nil
}

func (d *CSVSigClosure) Leaf() (*txscript.TapLeaf, error) {
	script, err := encodeCsvWithChecksigScript(d.Pubkey, d.Seconds)
	if err != nil {
		return nil, err
	}

	tapLeaf := txscript.NewBaseTapLeaf(script)
	return &tapLeaf, nil
}

func (d *CSVSigClosure) Decode(script []byte) (bool, error) {
	csvIndex := bytes.Index(
		script, []byte{txscript.OP_CHECKSEQUENCEVERIFY, txscript.OP_DROP},
	)
	if csvIndex == -1 || csvIndex == 0 {
		return false, nil
	}

	sequence := script[:csvIndex]
	if len(sequence) > 1 {
		sequence = sequence[1:]
	}

	seconds, err := common.BIP68DecodeSequence(sequence)
	if err != nil {
		return false, err
	}

	checksigScript := script[csvIndex+2:]
	valid, pubkey, err := decodeChecksigScript(checksigScript)
	if err != nil {
		return false, err
	}

	if !valid {
		return false, nil
	}

	rebuilt, err := encodeCsvWithChecksigScript(pubkey, seconds)
	if err != nil {
		return false, err
	}

	if !bytes.Equal(rebuilt, script) {
		return false, nil
	}

	d.Pubkey = pubkey
	d.Seconds = seconds

	return valid, nil
}

func decodeChecksigScript(script []byte) (bool, *secp256k1.PublicKey, error) {
	data32Index := bytes.Index(script, []byte{txscript.OP_DATA_32})
	if data32Index == -1 {
		return false, nil, nil
	}

	key := script[data32Index+1 : data32Index+33]
	if len(key) != 32 {
		return false, nil, nil
	}

	pubkey, err := schnorr.ParsePubKey(key)
	if err != nil {
		return false, nil, err
	}

	return true, pubkey, nil
}

// checkSequenceVerifyScript without checksig
func encodeCsvScript(seconds uint) ([]byte, error) {
	sequence, err := common.BIP68Sequence(seconds)
	if err != nil {
		return nil, err
	}

	return txscript.NewScriptBuilder().
		AddInt64(int64(sequence)).
		AddOps([]byte{
			txscript.OP_CHECKSEQUENCEVERIFY,
			txscript.OP_DROP,
		}).
		Script()
}

// checkSequenceVerifyScript + checksig
func encodeCsvWithChecksigScript(
	pubkey *secp256k1.PublicKey, seconds uint,
) ([]byte, error) {
	script, err := encodeChecksigScript(pubkey)
	if err != nil {
		return nil, err
	}

	csvScript, err := encodeCsvScript(seconds)
	if err != nil {
		return nil, err
	}

	return append(csvScript, script...), nil
}

func encodeChecksigScript(pubkey *secp256k1.PublicKey) ([]byte, error) {
	key := schnorr.SerializePubKey(pubkey)
	return txscript.NewScriptBuilder().AddData(key).
		AddOp(txscript.OP_CHECKSIG).Script()
}
