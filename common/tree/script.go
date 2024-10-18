package tree

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
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
	OP_INSPECTINPUTVALUE         = 0xc9
	OP_SUB64                     = 0xd8
)

type Closure interface {
	Leaf() (*taproot.TapElementsLeaf, error)
	Decode(script []byte) (bool, error)
}

type UnrollClosure struct {
	LeftKey, RightKey       *secp256k1.PublicKey
	LeftAmount, RightAmount uint64
	MinRelayFee             uint64
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

	closure = &UnrollClosure{}
	if valid, err := closure.Decode(script); err == nil && valid {
		return closure, nil
	}

	closure = &CSVSigClosure{}
	if valid, err := closure.Decode(script); err == nil && valid {
		return closure, nil
	}

	closure = &MultisigClosure{}
	if valid, err := closure.Decode(script); err == nil && valid {
		return closure, nil
	}

	return nil, fmt.Errorf("invalid closure script %s", hex.EncodeToString(script))
}

func (f *MultisigClosure) Leaf() (*taproot.TapElementsLeaf, error) {
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

func (d *CSVSigClosure) Leaf() (*taproot.TapElementsLeaf, error) {
	script, err := encodeCsvWithChecksigScript(d.Pubkey, d.Seconds)
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

func (c *UnrollClosure) isOneChild() bool {
	return c.RightKey == nil && c.MinRelayFee > 0
}

func (c *UnrollClosure) Leaf() (*taproot.TapElementsLeaf, error) {
	if c.LeftKey == nil {
		return nil, fmt.Errorf("left key is required")
	}

	if c.isOneChild() {
		branchScript := encodeOneChildIntrospectionScript(
			txscript.OP_0, schnorr.SerializePubKey(c.LeftKey), c.MinRelayFee,
		)
		leaf := taproot.NewBaseTapElementsLeaf(branchScript)
		return &leaf, nil
	}

	if c.LeftAmount == 0 {
		return nil, fmt.Errorf("left amount is required")
	}

	if c.RightKey == nil {
		return nil, fmt.Errorf("right key is required")
	}

	if c.RightAmount == 0 {
		return nil, fmt.Errorf("right amount is required")
	}

	nextScriptLeft := encodeIntrospectionScript(
		txscript.OP_0,
		schnorr.SerializePubKey(c.LeftKey), c.LeftAmount, c.RightKey != nil,
	)
	branchScript := append([]byte{}, nextScriptLeft...)

	nextScriptRight := encodeIntrospectionScript(
		txscript.OP_1, schnorr.SerializePubKey(c.RightKey), c.RightAmount, false,
	)
	branchScript = append(branchScript, nextScriptRight...)

	leaf := taproot.NewBaseTapElementsLeaf(branchScript)
	return &leaf, nil
}

func (c *UnrollClosure) Decode(script []byte) (valid bool, err error) {
	if len(script) != 52 && len(script) != 59 && len(script) != 104 {
		return false, nil
	}

	if len(script) == 59 {
		valid, pubkey, minrelayfee, err := decodeOneChildIntrospectionScript(script, txscript.OP_0)
		if err != nil {
			return false, err
		}

		if !valid {
			return false, nil
		}

		c.LeftKey = pubkey
		c.MinRelayFee = minrelayfee

		rebuilt, err := c.Leaf()
		if err != nil {
			return false, err
		}

		if !bytes.Equal(rebuilt.Script, script) {
			return false, nil
		}

		return true, nil
	}

	// len(script) > 52 if we have a right key, this is only for the backward compatibility with the old version of the closure
	validLeft, leftKey, leftAmount, err := decodeIntrospectionScript(
		script[:52], txscript.OP_0, len(script) > 52,
	)
	if err != nil {
		return false, err
	}

	if !validLeft {
		return false, nil
	}

	c.LeftAmount = leftAmount
	c.LeftKey = leftKey

	if len(script) == 52 {
		return true, nil
	}

	validRight, rightKey, rightAmount, err := decodeIntrospectionScript(
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

func decodeIntrospectionScript(
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

	rebuilt := encodeIntrospectionScript(
		expectedIndex, schnorr.SerializePubKey(pubkey), amount, isVerify,
	)
	if !bytes.Equal(rebuilt, script) {
		return false, nil, 0, nil
	}

	return true, pubkey, amount, nil
}

func decodeOneChildIntrospectionScript(
	script []byte, expectedIndex byte,
) (bool, *secp256k1.PublicKey, uint64, error) {
	if len(script) != 59 {
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

	value := script[len(script)-12 : len(script)-4]
	minrelayfee := binary.LittleEndian.Uint64(value)

	rebuilt := encodeOneChildIntrospectionScript(
		expectedIndex, schnorr.SerializePubKey(pubkey), minrelayfee,
	)

	if !bytes.Equal(rebuilt, script) {
		return false, nil, 0, nil
	}

	return true, pubkey, minrelayfee, nil
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

// encodeIntrospectionScript returns an introspection script that checks the
// script and the amount of the output at the given index verify will add an
// OP_EQUALVERIFY at the end of the script, otherwise it will add an OP_EQUAL
// length = 52 bytes
func encodeIntrospectionScript(
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

// encodeOneChildIntrospectionScript returns an introspection script that checks
// if the output at the given index has the correct script
// if the output has an amount equal to input_amount - minrelayfee
// length = 59 bytes
func encodeOneChildIntrospectionScript(
	index byte, taprootWitnessProgram []byte, minrelayfee uint64,
) []byte {
	minRelayFeeAmount := make([]byte, 8)
	binary.LittleEndian.PutUint64(minRelayFeeAmount, minrelayfee)

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
		index,
		OP_INSPECTOUTPUTVALUE,
		txscript.OP_1,
		txscript.OP_EQUALVERIFY,
		OP_PUSHCURRENTINPUTINDEX,
		OP_INSPECTINPUTVALUE,
		txscript.OP_1,
		txscript.OP_EQUALVERIFY,
		txscript.OP_DATA_8,
	}...)

	script = append(script, minRelayFeeAmount...)

	script = append(script, []byte{
		OP_SUB64,
		txscript.OP_1,
		txscript.OP_EQUALVERIFY,
		txscript.OP_EQUAL,
	}...)

	return script
}
