package tree

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/ark-network/ark/common"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/vulpemventures/go-elements/taproot"
)

const (
	OP_INSPECTOUTPUTSCRIPTPUBKEY = 0xd1
	OP_INSPECTOUTPUTVALUE        = 0xcf
	OP_PUSHCURRENTINPUTINDEX     = 0xcd
)

type Closure interface {
	Leaf() (*taproot.TapElementsLeaf, error)
	Decode(script []byte) (bool, error)
}

type UnrollClosure struct {
	LeftKey, RightKey       *secp256k1.PublicKey
	LeftAmount, RightAmount uint64
}

type CSVSigClosure struct {
	Pubkey  *secp256k1.PublicKey
	Seconds uint
}

type ForfeitClosure struct {
	Pubkey    *secp256k1.PublicKey
	AspPubkey *secp256k1.PublicKey
}

func DecodeClosure(script []byte) (Closure, error) {
	var closure Closure

	closure = &UnrollClosure{}
	if valid, err := closure.Decode(script); err == nil && valid {
		return closure, nil
	}

	closure = &CSVSigClosure{}
	if valid, err := closure.Decode(script); err == nil && valid {
		return closure, nil
	}

	closure = &ForfeitClosure{}
	if valid, err := closure.Decode(script); err == nil && valid {
		return closure, nil
	}

	return nil, fmt.Errorf("invalid closure script")

}

func (f *ForfeitClosure) Leaf() (*taproot.TapElementsLeaf, error) {
	aspKeyBytes := schnorr.SerializePubKey(f.AspPubkey)
	userKeyBytes := schnorr.SerializePubKey(f.Pubkey)

	script, err := txscript.NewScriptBuilder().AddData(aspKeyBytes).
		AddOp(txscript.OP_CHECKSIGVERIFY).AddData(userKeyBytes).
		AddOp(txscript.OP_CHECKSIG).Script()
	if err != nil {
		return nil, err
	}

	tapLeaf := taproot.NewBaseTapElementsLeaf(script)
	return &tapLeaf, nil
}

func (f *ForfeitClosure) Decode(script []byte) (bool, error) {
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

func (d *CSVSigClosure) Leaf() (*taproot.TapElementsLeaf, error) {
	script, err := csvChecksigScript(d.Pubkey, d.Seconds)
	if err != nil {
		return nil, err
	}

	tapLeaf := taproot.NewBaseTapElementsLeaf(script)
	return &tapLeaf, nil
}

func (d *CSVSigClosure) Decode(script []byte) (bool, error) {
	csvIndex := bytes.Index(
		script, []byte{txscript.OP_CHECKSEQUENCEVERIFY, txscript.OP_DROP},
	)
	if csvIndex == -1 || csvIndex == 0 {
		return false, nil
	}

	sequence := script[1:csvIndex]

	seconds, err := common.BIP68Decode(sequence)
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

	rebuilt, err := csvChecksigScript(pubkey, seconds)
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

func (c *UnrollClosure) Leaf() (*taproot.TapElementsLeaf, error) {
	if c.LeftKey == nil || c.LeftAmount == 0 {
		return nil, fmt.Errorf("left key and amount are required")
	}

	nextScriptLeft := getIntrospectionScript(
		txscript.OP_0,
		schnorr.SerializePubKey(c.LeftKey), c.LeftAmount, c.RightKey != nil,
	)
	branchScript := append([]byte{}, nextScriptLeft...)
	if c.RightKey != nil {
		if c.RightAmount == 0 {
			return nil, fmt.Errorf("right amount is required")
		}

		nextScriptRight := getIntrospectionScript(
			txscript.OP_1, schnorr.SerializePubKey(c.RightKey), c.RightAmount, false,
		)
		branchScript = append(branchScript, nextScriptRight...)
	}
	leaf := taproot.NewBaseTapElementsLeaf(branchScript)
	return &leaf, nil
}

func (c *UnrollClosure) Decode(script []byte) (valid bool, err error) {
	if len(script) != 52 && len(script) != 104 {
		return false, nil
	}

	isLeftOnly := len(script) == 52

	validLeft, leftKey, leftAmount, err := decodeWithOutputScript(
		script[:52], txscript.OP_0, !isLeftOnly,
	)
	if err != nil {
		return false, err
	}

	if !validLeft {
		return false, nil
	}

	c.LeftAmount = leftAmount
	c.LeftKey = leftKey

	if isLeftOnly {
		return true, nil
	}

	validRight, rightKey, rightAmount, err := decodeWithOutputScript(
		script[52:], txscript.OP_1, false,
	)
	if err != nil {
		return false, err
	}

	if !validRight {
		return false, nil
	}

	c.RightAmount = rightAmount
	c.RightKey = rightKey

	rebuilt, err := c.Leaf()
	if err != nil {
		return false, err
	}

	if !bytes.Equal(rebuilt.Script, script) {
		return false, nil
	}

	return true, nil
}

func decodeWithOutputScript(
	script []byte, expectedIndex byte, isVerify bool,
) (bool, *secp256k1.PublicKey, uint64, error) {
	if len(script) != 52 {
		return false, nil, 0, nil
	}

	if script[0] != expectedIndex {
		return false, nil, 0, nil
	}

	// 32 bytes for the witness program
	pubkey, err := schnorr.ParsePubKey(script[5 : 5+32])
	if err != nil {
		return false, nil, 0, err
	}

	// verify the index of INSPECTVALUE
	if script[38] != expectedIndex {
		return false, nil, 0, nil
	}

	// 8 bytes for the amount
	amountBytes := script[len(script)-9 : len(script)-1]
	amount := binary.LittleEndian.Uint64(amountBytes)

	rebuilt := getIntrospectionScript(
		expectedIndex, schnorr.SerializePubKey(pubkey), amount, isVerify,
	)
	if !bytes.Equal(rebuilt, script) {
		return false, nil, 0, nil
	}

	return true, pubkey, amount, nil
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
func checkSequenceVerifyScript(seconds uint) ([]byte, error) {
	sequence, err := common.BIP68Encode(seconds)
	if err != nil {
		return nil, err
	}

	return txscript.NewScriptBuilder().AddData(sequence).AddOps([]byte{
		txscript.OP_CHECKSEQUENCEVERIFY,
		txscript.OP_DROP,
	}).Script()
}

// checkSequenceVerifyScript + checksig
func csvChecksigScript(
	pubkey *secp256k1.PublicKey, seconds uint,
) ([]byte, error) {
	script, err := checksigScript(pubkey)
	if err != nil {
		return nil, err
	}

	csvScript, err := checkSequenceVerifyScript(seconds)
	if err != nil {
		return nil, err
	}

	return append(csvScript, script...), nil
}

func checksigScript(pubkey *secp256k1.PublicKey) ([]byte, error) {
	key := schnorr.SerializePubKey(pubkey)
	return txscript.NewScriptBuilder().AddData(key).
		AddOp(txscript.OP_CHECKSIG).Script()
}

// getIntrospectionScript returns an introspection script that checks the
// script and the amount of the output at the given index verify will add an
// OP_EQUALVERIFY at the end of the script, otherwise it will add an OP_EQUAL
// length = 52 bytes
func getIntrospectionScript(
	index byte, taprootWitnessProgram []byte, amount uint64, verify bool,
) []byte {
	amountBuffer := make([]byte, 8)
	binary.LittleEndian.PutUint64(amountBuffer, amount)

	script := []byte{
		index,
		OP_INSPECTOUTPUTSCRIPTPUBKEY,
		txscript.OP_1,
		txscript.OP_EQUALVERIFY,
		txscript.OP_DATA_32,
	}

	script = append(script, taprootWitnessProgram...)
	script = append(script, []byte{
		txscript.OP_EQUALVERIFY,
	}...)
	script = append(script, index)
	script = append(script, []byte{
		OP_INSPECTOUTPUTVALUE,
		txscript.OP_1,
		txscript.OP_EQUALVERIFY,
		txscript.OP_DATA_8,
	}...)
	script = append(script, amountBuffer...)
	if verify {
		script = append(script, []byte{
			txscript.OP_EQUALVERIFY,
		}...)
	} else {
		script = append(script, []byte{
			txscript.OP_EQUAL,
		}...)
	}

	return script
}
