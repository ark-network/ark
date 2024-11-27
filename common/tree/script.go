package tree

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/ark-network/ark/common"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

const (
	OP_INSPECTOUTPUTSCRIPTPUBKEY = 0xd1
	OP_INSPECTOUTPUTVALUE        = 0xcf
	OP_PUSHCURRENTINPUTINDEX     = 0xcd
	OP_INSPECTINPUTVALUE         = 0xc9
	OP_SUB64                     = 0xd8
)

type MultisigType int

const (
	MultisigTypeChecksig MultisigType = iota
	MultisigTypeChecksigAdd
)

type Closure interface {
	Script() ([]byte, error)
	Decode(script []byte) (bool, error)
	// WitnessSize returns the size of the witness excluding the script and control block
	WitnessSize() int
	Witness(controlBlock []byte, signatures map[string][]byte) (wire.TxWitness, error)
}

// UnrollClosure is liquid-only tapscript letting to enforce
// unrollable UTXO without musig.
type UnrollClosure struct {
	LeftKey, RightKey       *secp256k1.PublicKey
	LeftAmount, RightAmount uint64
	MinRelayFee             uint64
}

// MultisigClosure is a closure that contains a list of public keys and a
// CHECKSIG for each key. The witness size is 64 bytes per key, admitting the
// sighash type is SIGHASH_DEFAULT.
type MultisigClosure struct {
	PubKeys []*secp256k1.PublicKey
	Type    MultisigType
}

// CSVSigClosure is a closure that contains a list of public keys and a
// CHECKSEQUENCEVERIFY. The witness size is 64 bytes per key, admitting
// the sighash type is SIGHASH_DEFAULT.
type CSVSigClosure struct {
	MultisigClosure
	Locktime common.Locktime
}

// CLTVMultisigClosure is a closure that contains a list of public keys and a
// CHECKLOCKTIMEVERIFY. The witness size is 64 bytes per key, admitting
// the sighash type is SIGHASH_DEFAULT.
type CLTVMultisigClosure struct {
	MultisigClosure
	Locktime common.Locktime
}

func DecodeClosure(script []byte) (Closure, error) {
	types := []Closure{
		&CSVSigClosure{},
		&CLTVMultisigClosure{},
		&MultisigClosure{},
		&UnrollClosure{},
	}

	for _, closure := range types {
		if valid, err := closure.Decode(script); err == nil && valid {
			return closure, nil
		}
	}

	return nil, fmt.Errorf("invalid closure script %s", hex.EncodeToString(script))
}

func (f *MultisigClosure) WitnessSize() int {
	return 64 * len(f.PubKeys)
}

func (f *MultisigClosure) Script() ([]byte, error) {
	scriptBuilder := txscript.NewScriptBuilder()

	switch f.Type {
	case MultisigTypeChecksig:
		for i, pubkey := range f.PubKeys {
			scriptBuilder.AddData(schnorr.SerializePubKey(pubkey))
			if i == len(f.PubKeys)-1 {
				scriptBuilder.AddOp(txscript.OP_CHECKSIG)
				continue
			}
			scriptBuilder.AddOp(txscript.OP_CHECKSIGVERIFY)
		}
	case MultisigTypeChecksigAdd:
		for i, pubkey := range f.PubKeys {
			scriptBuilder.AddData(schnorr.SerializePubKey(pubkey))
			if i == 0 {
				scriptBuilder.AddOp(txscript.OP_CHECKSIG)
				continue
			}
			scriptBuilder.AddOp(txscript.OP_CHECKSIGADD)
		}
		scriptBuilder.AddInt64(int64(len(f.PubKeys)))
		scriptBuilder.AddOp(txscript.OP_EQUAL)
	}

	return scriptBuilder.Script()
}

func (f *MultisigClosure) Decode(script []byte) (bool, error) {
	if len(script) == 0 {
		return false, fmt.Errorf("empty script")
	}

	valid, err := f.decodeChecksig(script)
	if err != nil {
		return false, fmt.Errorf("failed to decode checksig: %w", err)
	}
	if valid {
		return true, nil
	}

	valid, err = f.decodeChecksigAdd(script)
	if err != nil {
		return false, fmt.Errorf("failed to decode checksigadd: %w", err)
	}
	if valid {
		return valid, nil
	}

	return false, nil
}

func (f *MultisigClosure) decodeChecksigAdd(script []byte) (bool, error) {
	pubkeys := make([]*secp256k1.PublicKey, 0)

	// Keep track of position in script
	pos := 0

	for pos < len(script) {
		// Check for 33-byte data push (32 bytes for pubkey + 1 byte for OP_DATA)
		if pos+33 > len(script) {
			break
		}

		// Verify we have a 32-byte data push
		if script[pos] != txscript.OP_DATA_32 {
			return false, nil
		}

		// Parse the public key
		pubkey, err := schnorr.ParsePubKey(script[pos+1 : pos+33])
		if err != nil {
			return false, err
		}

		pubkeys = append(pubkeys, pubkey)
		pos += 33

		// Check if we've reached the end
		if pos >= len(script) {
			return false, nil
		}

		// Check for CHECKSIG or CHECKSIGADD pattern
		if len(pubkeys) == 1 && script[pos] == txscript.OP_CHECKSIG {
			pos++
		} else if len(pubkeys) > 1 && script[pos] == txscript.OP_CHECKSIGADD {
			pos++
		} else {
			return false, nil
		}
	}

	lastOp := script[len(script)-1]
	if lastOp != txscript.OP_EQUAL {
		return false, nil
	}

	// Verify we found at least one public key
	if len(pubkeys) == 0 {
		return false, nil
	}

	f.PubKeys = pubkeys
	f.Type = MultisigTypeChecksigAdd

	// Verify the script matches what we would generate
	rebuilt, err := f.Script()
	if err != nil {
		f.PubKeys = nil
		f.Type = 0
		return false, err
	}

	if !bytes.Equal(rebuilt, script) {
		f.PubKeys = nil
		f.Type = 0
		return false, nil
	}

	return true, nil
}

func (f *MultisigClosure) decodeChecksig(script []byte) (bool, error) {
	pubkeys := make([]*secp256k1.PublicKey, 0)

	// Keep track of position in script
	pos := 0

	for pos < len(script) {
		// Check for 33-byte data push (32 bytes for pubkey + 1 byte for OP_DATA)
		if pos+33 > len(script) {
			return false, nil
		}

		// Verify we have a 32-byte data push
		if script[pos] != txscript.OP_DATA_32 {
			return false, nil
		}

		// Parse the public key
		pubkey, err := schnorr.ParsePubKey(script[pos+1 : pos+33])
		if err != nil {
			return false, err
		}

		pubkeys = append(pubkeys, pubkey)
		pos += 33

		// Check if we've reached the end
		if pos >= len(script) {
			return false, nil
		}

		// Next byte should be either CHECKSIG (last key) or CHECKSIGVERIFY
		if script[pos] == txscript.OP_CHECKSIG {
			// This should be the last operation
			if pos != len(script)-1 {
				return false, nil
			}
			break
		} else if script[pos] == txscript.OP_CHECKSIGVERIFY {
			pos++
			continue
		} else {
			return false, nil
		}
	}

	// Verify we found at least one public key
	if len(pubkeys) == 0 {
		return false, nil
	}

	f.PubKeys = pubkeys
	f.Type = MultisigTypeChecksig

	// Verify the script matches what we would generate
	rebuilt, err := f.Script()
	if err != nil {
		f.PubKeys = nil
		f.Type = 0
		return false, err
	}

	if !bytes.Equal(rebuilt, script) {
		f.PubKeys = nil
		f.Type = 0
		return false, nil
	}

	return true, nil
}

func (f *MultisigClosure) Witness(controlBlock []byte, signatures map[string][]byte) (wire.TxWitness, error) {
	// Create witness stack with capacity for all signatures plus script and control block
	witness := make(wire.TxWitness, 0, len(f.PubKeys)+2)

	// Add signatures in the reverse order as public keys
	for i := len(f.PubKeys) - 1; i >= 0; i-- {
		pubkey := f.PubKeys[i]
		sig, ok := signatures[hex.EncodeToString(schnorr.SerializePubKey(pubkey))]
		if !ok {
			return nil, fmt.Errorf("missing signature for public key %x", schnorr.SerializePubKey(pubkey))
		}
		witness = append(witness, sig)
	}

	// Get script
	script, err := f.Script()
	if err != nil {
		return nil, fmt.Errorf("failed to generate script: %w", err)
	}

	// Add script and control block
	witness = append(witness, script)
	witness = append(witness, controlBlock)

	return witness, nil
}

func (f *CSVSigClosure) Witness(controlBlock []byte, signatures map[string][]byte) (wire.TxWitness, error) {
	multisigWitness, err := f.MultisigClosure.Witness(controlBlock, signatures)
	if err != nil {
		return nil, err
	}

	script, err := f.Script()
	if err != nil {
		return nil, fmt.Errorf("failed to generate script: %w", err)
	}

	// replace script with csv script
	multisigWitness[len(multisigWitness)-2] = script

	return multisigWitness, nil
}

func (f *CSVSigClosure) WitnessSize() int {
	return f.MultisigClosure.WitnessSize()
}

func (d *CSVSigClosure) Script() ([]byte, error) {
	sequence, err := common.BIP68Sequence(d.Locktime)
	if err != nil {
		return nil, err
	}

	csvScript, err := txscript.NewScriptBuilder().
		AddInt64(int64(sequence)).
		AddOps([]byte{
			txscript.OP_CHECKSEQUENCEVERIFY,
			txscript.OP_DROP,
		}).
		Script()
	if err != nil {
		return nil, err
	}

	multisigScript, err := d.MultisigClosure.Script()
	if err != nil {
		return nil, err
	}

	return append(csvScript, multisigScript...), nil
}

func (d *CSVSigClosure) Decode(script []byte) (bool, error) {
	if len(script) == 0 {
		return false, fmt.Errorf("empty script")
	}

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

	locktime, err := common.BIP68DecodeSequence(sequence)
	if err != nil {
		return false, err
	}

	multisigClosure := &MultisigClosure{}
	valid, err := multisigClosure.Decode(script[csvIndex+2:])
	if err != nil {
		return false, err
	}

	if !valid {
		return false, nil
	}

	d.Locktime = *locktime
	d.MultisigClosure = *multisigClosure

	return valid, nil
}

func (c *UnrollClosure) WitnessSize() int {
	return 0
}

func (c *UnrollClosure) isOneChild() bool {
	return c.RightKey == nil && c.MinRelayFee > 0
}

func (c *UnrollClosure) Script() ([]byte, error) {
	if c.LeftKey == nil {
		return nil, fmt.Errorf("left key is required")
	}

	if c.isOneChild() {
		branchScript := encodeOneChildIntrospectionScript(
			txscript.OP_0, schnorr.SerializePubKey(c.LeftKey), c.MinRelayFee,
		)
		return branchScript, nil
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

	return branchScript, nil
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

		rebuilt, err := c.Script()
		if err != nil {
			return false, err
		}

		if !bytes.Equal(rebuilt, script) {
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

	rebuilt, err := c.Script()
	if err != nil {
		return false, err
	}

	if !bytes.Equal(rebuilt, script) {
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

func (c *UnrollClosure) Witness(controlBlock []byte, _ map[string][]byte) (wire.TxWitness, error) {
	script, err := c.Script()
	if err != nil {
		return nil, fmt.Errorf("failed to generate script: %w", err)
	}

	// UnrollClosure only needs script and control block
	return wire.TxWitness{script, controlBlock}, nil
}

func (f *CLTVMultisigClosure) Witness(controlBlock []byte, signatures map[string][]byte) (wire.TxWitness, error) {
	multisigWitness, err := f.MultisigClosure.Witness(controlBlock, signatures)
	if err != nil {
		return nil, err
	}

	script, err := f.Script()
	if err != nil {
		return nil, fmt.Errorf("failed to generate script: %w", err)
	}

	// replace script with cltv script
	multisigWitness[len(multisigWitness)-2] = script

	return multisigWitness, nil
}

func (f *CLTVMultisigClosure) WitnessSize() int {
	return f.MultisigClosure.WitnessSize()
}

func (d *CLTVMultisigClosure) Script() ([]byte, error) {
	locktime, err := common.BIP68Sequence(d.Locktime)
	if err != nil {
		return nil, err
	}

	cltvScript, err := txscript.NewScriptBuilder().
		AddInt64(int64(locktime)).
		AddOps([]byte{
			txscript.OP_CHECKLOCKTIMEVERIFY,
			txscript.OP_DROP,
		}).
		Script()
	if err != nil {
		return nil, err
	}

	multisigScript, err := d.MultisigClosure.Script()
	if err != nil {
		return nil, err
	}

	return append(cltvScript, multisigScript...), nil
}

func (d *CLTVMultisigClosure) Decode(script []byte) (bool, error) {
	if len(script) == 0 {
		return false, fmt.Errorf("empty script")
	}

	cltvIndex := bytes.Index(
		script, []byte{txscript.OP_CHECKLOCKTIMEVERIFY, txscript.OP_DROP},
	)
	if cltvIndex == -1 || cltvIndex == 0 {
		return false, nil
	}

	locktime := script[:cltvIndex]
	if len(locktime) > 1 {
		locktime = locktime[1:]
	}

	locktimeValue, err := common.BIP68DecodeSequence(locktime)
	if err != nil {
		return false, err
	}

	multisigClosure := &MultisigClosure{}
	valid, err := multisigClosure.Decode(script[cltvIndex+2:])
	if err != nil {
		return false, err
	}

	if !valid {
		return false, nil
	}

	d.Locktime = *locktimeValue
	d.MultisigClosure = *multisigClosure

	return valid, nil
}
