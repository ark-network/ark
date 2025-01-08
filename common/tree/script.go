package tree

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

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

const ConditionWitnessKey = "condition"

// forbiddenOpcodes are opcodes that are not allowed in a condition script
var forbiddenOpcodes = []byte{
	txscript.OP_CHECKMULTISIG,
	txscript.OP_CHECKSIG,
	txscript.OP_CHECKSIGVERIFY,
	txscript.OP_CHECKSIGADD,
	txscript.OP_CHECKMULTISIGVERIFY,
	txscript.OP_CHECKLOCKTIMEVERIFY,
	txscript.OP_CHECKSEQUENCEVERIFY,
}

type Closure interface {
	Script() ([]byte, error)
	Decode(script []byte) (bool, error)
	// WitnessSize returns the size of the witness excluding the script and control block
	// extraWitnessSize is here to count the condition witness size
	// or any other witness size that can't be computed from the script
	WitnessSize(extraWitnessSize ...int) int
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

// CSVMultisigClosure is a closure that contains a list of public keys and a
// CHECKSEQUENCEVERIFY. The witness size is 64 bytes per key, admitting
// the sighash type is SIGHASH_DEFAULT.
type CSVMultisigClosure struct {
	MultisigClosure
	Locktime common.RelativeLocktime
}

// CLTVMultisigClosure is a closure that contains a list of public keys and a
// CHECKLOCKTIMEVERIFY. The witness size is 64 bytes per key, admitting
// the sighash type is SIGHASH_DEFAULT.
type CLTVMultisigClosure struct {
	MultisigClosure
	Locktime common.AbsoluteLocktime
}

// ConditionMultisigClosure is a closure that contains a condition and a
// multisig closure. The condition is a boolean script that is executed with the
// multisig witness.
type ConditionMultisigClosure struct {
	MultisigClosure
	Condition []byte
}

// ConditionCSVMultisigClosure is a closure that contains a condition and a
// CSV multisig closure. The condition is a boolean script that is executed with the
// multisig witness.
type ConditionCSVMultisigClosure struct {
	CSVMultisigClosure
	Condition []byte
}

func DecodeClosure(script []byte) (Closure, error) {
	if len(script) == 0 {
		return nil, fmt.Errorf("cannot decode empty script")
	}

	types := []struct {
		closure Closure
		name    string
	}{
		{&CSVMultisigClosure{}, "CSV Multisig"},
		{&CLTVMultisigClosure{}, "CLTV Multisig"},
		{&MultisigClosure{}, "Multisig"},
		{&ConditionMultisigClosure{}, "Condition Multisig"},
		{&ConditionCSVMultisigClosure{}, "Condition CSV Multisig"},
		{&UnrollClosure{}, "Unroll"},
	}

	var decodeErr []string
	for _, t := range types {
		scriptCopy := make([]byte, len(script))
		copy(scriptCopy, script)
		valid, err := t.closure.Decode(scriptCopy)
		if err != nil {
			decodeErr = append(decodeErr, fmt.Sprintf("%s: %v", t.name, err))
			continue
		}
		if valid {
			return t.closure, nil
		}
	}

	if len(decodeErr) > 0 {
		return nil, fmt.Errorf(
			"failed to decode script %x.\n%s", script, strings.Join(decodeErr, "\n"),
		)
	}

	return nil, fmt.Errorf("script does not match any known closure type: %s",
		hex.EncodeToString(script))
}

func (f *MultisigClosure) WitnessSize(_ ...int) int {
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
		scriptBuilder.AddOp(txscript.OP_NUMEQUAL)
	}

	return scriptBuilder.Script()
}

func (f *MultisigClosure) Decode(script []byte) (bool, error) {
	if len(script) == 0 {
		return false, fmt.Errorf("failed to decode: script is empty")
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
	tokenizer := txscript.MakeScriptTokenizer(0, script)

	pubkeys := make([]*secp256k1.PublicKey, 0)

	for tokenizer.Next() {
		// Stop processing if a small integer opcode is encountered,
		// indicating the required threshold for signature validation.
		if txscript.IsSmallInt(tokenizer.Opcode()) {
			break
		}

		// Verify we have a 32-byte data push
		if tokenizer.Opcode() != txscript.OP_DATA_32 {
			return false, nil
		}

		// Parse the public key
		pubkey, err := schnorr.ParsePubKey(tokenizer.Data())
		if err != nil {
			return false, err
		}

		pubkeys = append(pubkeys, pubkey)

		// Check if we've reached the end
		if !tokenizer.Next() {
			return false, nil
		}

		if tokenizer.Opcode() == txscript.OP_CHECKSIGADD || tokenizer.Opcode() == txscript.OP_CHECKSIG {
			continue
		} else {
			return false, nil
		}
	}

	// Verify public keys len
	if tokenizer.Err() != nil || len(pubkeys) != txscript.AsSmallInt(tokenizer.Opcode()) {
		return false, nil
	}

	if !tokenizer.Next() || tokenizer.Opcode() != txscript.OP_NUMEQUAL {
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
	tokenizer := txscript.MakeScriptTokenizer(0, script)

	pubkeys := make([]*secp256k1.PublicKey, 0)

	for tokenizer.Next() {
		// Verify we have a 32-byte data push
		if tokenizer.Opcode() != txscript.OP_DATA_32 {
			return false, nil
		}

		// Parse the public key
		pubkey, err := schnorr.ParsePubKey(tokenizer.Data())
		if err != nil {
			return false, err
		}

		pubkeys = append(pubkeys, pubkey)

		// Check if we've reached the end
		if !tokenizer.Next() {
			return false, nil
		}

		if tokenizer.Opcode() == txscript.OP_CHECKSIGVERIFY {
			continue
		} else {
			break
		}
	}

	// This should be the last operation
	if tokenizer.Err() != nil || tokenizer.Opcode() != txscript.OP_CHECKSIG {
		return false, nil
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

func (f *CSVMultisigClosure) Witness(controlBlock []byte, signatures map[string][]byte) (wire.TxWitness, error) {
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

func (f *CSVMultisigClosure) WitnessSize(extraWitnessSizes ...int) int {
	return f.MultisigClosure.WitnessSize(extraWitnessSizes...)
}

func (d *CSVMultisigClosure) Script() ([]byte, error) {
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

func (d *CSVMultisigClosure) Decode(script []byte) (bool, error) {
	if len(script) == 0 {
		return false, fmt.Errorf("empty script")
	}

	tokenizer := txscript.MakeScriptTokenizer(0, script)

	// Advance the tokenizer to the next token and extract the sequence.
	// If the opcode represents a small integer, store it as a single byte in the sequence.
	// Otherwise, extract the data directly from the tokenizer.
	if !tokenizer.Next() {
		return false, nil
	}

	var sequence []byte
	if txscript.IsSmallInt(tokenizer.Opcode()) {
		sequence = []byte{tokenizer.Opcode()}
	} else {
		sequence = tokenizer.Data()
	}

	for _, opCode := range []byte{txscript.OP_CHECKSEQUENCEVERIFY, txscript.OP_DROP} {

		if !tokenizer.Next() || tokenizer.Opcode() != opCode {
			return false, nil
		}

	}

	locktime, err := common.BIP68DecodeSequence(sequence)
	if err != nil {
		return false, err
	}

	multisigClosure := &MultisigClosure{}
	subScript := tokenizer.Script()[tokenizer.ByteIndex():]
	valid, err := multisigClosure.Decode(subScript)
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

func (c *UnrollClosure) WitnessSize(_ ...int) int {
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

func (f *CLTVMultisigClosure) WitnessSize(extraWitnessSizes ...int) int {
	return f.MultisigClosure.WitnessSize(extraWitnessSizes...)
}

func (d *CLTVMultisigClosure) Script() ([]byte, error) {
	cltvScript, err := txscript.NewScriptBuilder().
		AddInt64(int64(d.Locktime)).
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

	tokenizer := txscript.MakeScriptTokenizer(0, script)

	// Advance the tokenizer to the next token and extract the locktime.
	// If the opcode represents a small integer, store it as a single byte in the sequence.
	// Otherwise, extract the data directly from the tokenizer.
	if !tokenizer.Next() {
		return false, nil
	}

	var locktime []byte
	if txscript.IsSmallInt(tokenizer.Opcode()) {
		locktime = []byte{tokenizer.Opcode()}
	} else {
		locktime = tokenizer.Data()
	}

	for _, opCode := range []byte{txscript.OP_CHECKLOCKTIMEVERIFY, txscript.OP_DROP} {

		if !tokenizer.Next() || tokenizer.Opcode() != opCode {
			return false, nil
		}
	}

	var locktimeValue uint32
	// read uint32 from bytes
	if len(locktime) >= 3 {
		locktimeValue = binary.LittleEndian.Uint32(locktime)
	} else {
		locktimeValue = uint32(binary.LittleEndian.Uint16(locktime))
	}

	multisigClosure := &MultisigClosure{}
	subScript := tokenizer.Script()[tokenizer.ByteIndex():]
	valid, err := multisigClosure.Decode(subScript)
	if err != nil {
		return false, err
	}

	if !valid {
		return false, nil
	}

	d.Locktime = common.AbsoluteLocktime(locktimeValue)
	d.MultisigClosure = *multisigClosure

	return valid, nil
}

// ExecuteBoolScript run the script with the provided witness as argument
// the result must be a boolean value accepted by OP_IF / OP_NOTIF opcodes
func ExecuteBoolScript(script []byte, witness wire.TxWitness) (bool, error) {
	// make sure the script doesn't contain any introspections opcodes (sig or locktime)
	tokenizer := txscript.MakeScriptTokenizer(0, script)
	for tokenizer.Next() {
		for _, opcode := range forbiddenOpcodes {
			if tokenizer.OpcodePosition() != -1 && tokenizer.Opcode() == opcode {
				return false, fmt.Errorf("forbidden opcode %x", opcode)
			}
		}
	}

	// Create a fake transaction with minimal required fields
	// this is needed to instantiate the script engine without a tx
	// as we don't validate any tx data, we just need to have a valid tx structure
	fakeTx := &wire.MsgTx{
		Version: 2,
		TxIn:    []*wire.TxIn{{Sequence: 0xffffffff}}, // At least one input required
		TxOut:   []*wire.TxOut{{Value: 0}},            // At least one output required
	}

	// Create a new script engine with the fake tx
	vm, err := txscript.NewEngine(
		script,
		fakeTx,
		0, // Input index
		txscript.ScriptVerifyTaproot,
		nil,
		nil,
		0,
		nil,
	)
	if err != nil {
		return false, fmt.Errorf("failed to create script engine: %w", err)
	}

	vm.SetStack(witness)

	// Execute the script with the provided witness
	if err := vm.Execute(); err != nil {
		if scriptError, ok := err.(txscript.Error); ok {
			if scriptError.ErrorCode == txscript.ErrEvalFalse {
				return false, nil
			}
		}
		return false, err
	}

	finalStack := vm.GetStack()

	if len(finalStack) != 0 {
		return false, fmt.Errorf("script must return zero value on the stack, got %d", len(finalStack))
	}

	return true, nil
}

func ReadTxWitness(witnessSerialized []byte) (wire.TxWitness, error) {
	r := bytes.NewReader(witnessSerialized)

	// first we extract the number of witness elements
	witCount, err := wire.ReadVarInt(r, 0)
	if err != nil {
		return nil, err
	}

	// read each witness item
	witness := make(wire.TxWitness, witCount)
	for i := uint64(0); i < witCount; i++ {
		witness[i], err = wire.ReadVarBytes(r, 0, txscript.MaxScriptSize, "witness")
		if err != nil {
			return nil, err
		}
	}

	return witness, nil
}
func (f *ConditionMultisigClosure) WitnessSize(conditionWitnessSizes ...int) int {
	var sum int
	for _, size := range conditionWitnessSizes {
		sum += size
	}

	return f.MultisigClosure.WitnessSize() + sum
}

func (f *ConditionMultisigClosure) Script() ([]byte, error) {
	scriptBuilder := txscript.NewScriptBuilder()

	scriptBuilder.AddOps(f.Condition)
	scriptBuilder.AddOp(txscript.OP_VERIFY)

	// Add the multisig script
	multisigScript, err := f.MultisigClosure.Script()
	if err != nil {
		return nil, fmt.Errorf("failed to generate multisig script: %w", err)
	}
	scriptBuilder.AddOps(multisigScript)

	return scriptBuilder.Script()
}

func (f *ConditionMultisigClosure) Decode(script []byte) (bool, error) {
	tokenizer := txscript.MakeScriptTokenizer(0, script)

	if len(tokenizer.Script()) == 0 {
		return false, fmt.Errorf("empty script")
	}

	condition := make([]byte, 0)
	for tokenizer.Next() {
		if tokenizer.Opcode() == txscript.OP_VERIFY {
			break
		} else {
			condition = append(condition, tokenizer.Opcode())
			if len(tokenizer.Data()) > 0 {
				condition = append(condition, tokenizer.Data()...)
			}
		}
	}

	f.Condition = condition

	// Decode multisig closure
	subScript := tokenizer.Script()[tokenizer.ByteIndex():]
	valid, err := f.MultisigClosure.Decode(subScript)
	if err != nil || !valid {
		return false, err
	}

	// Verify the script matches what we would generate
	rebuilt, err := f.Script()
	if err != nil {
		return false, err
	}

	return bytes.Equal(rebuilt, script), nil
}

func (f *ConditionMultisigClosure) Witness(controlBlock []byte, args map[string][]byte) (wire.TxWitness, error) {
	script, err := f.Script()
	if err != nil {
		return nil, fmt.Errorf("failed to generate script: %w", err)
	}

	// Read and execute condition witness
	condWitness, err := ReadTxWitness(args[ConditionWitnessKey])
	if err != nil {
		return nil, fmt.Errorf("failed to read condition witness: %w", err)
	}

	returnValue, err := ExecuteBoolScript(f.Condition, condWitness)
	if err != nil {
		return nil, fmt.Errorf("failed to execute condition: %w", err)
	}

	if !returnValue {
		return nil, fmt.Errorf("condition evaluated to false")
	}

	// Get multisig witness
	multisigWitness, err := f.MultisigClosure.Witness(controlBlock, args)
	if err != nil {
		return nil, err
	}

	multisigWitness = multisigWitness[:len(multisigWitness)-2] // remove control block and script
	witness := append(multisigWitness, condWitness...)
	witness = append(witness, script)
	witness = append(witness, controlBlock)

	return witness, nil
}

func (f *ConditionCSVMultisigClosure) WitnessSize(conditionWitnessSizes ...int) int {
	var sum int
	for _, size := range conditionWitnessSizes {
		sum += size
	}

	return f.CSVMultisigClosure.WitnessSize() + sum
}

func (f *ConditionCSVMultisigClosure) Script() ([]byte, error) {
	scriptBuilder := txscript.NewScriptBuilder()

	scriptBuilder.AddOps(f.Condition)
	scriptBuilder.AddOp(txscript.OP_VERIFY)

	// Add the multisig script
	multisigScript, err := f.CSVMultisigClosure.Script()
	if err != nil {
		return nil, fmt.Errorf("failed to generate multisig script: %w", err)
	}
	scriptBuilder.AddOps(multisigScript)

	return scriptBuilder.Script()
}

func (f *ConditionCSVMultisigClosure) Decode(script []byte) (bool, error) {
	tokenizer := txscript.MakeScriptTokenizer(0, script)

	if len(tokenizer.Script()) == 0 {
		return false, fmt.Errorf("empty script")
	}

	condition := make([]byte, 0)
	for tokenizer.Next() {
		if tokenizer.Opcode() == txscript.OP_VERIFY {
			break
		} else {
			condition = append(condition, tokenizer.Opcode())
			if len(tokenizer.Data()) > 0 {
				condition = append(condition, tokenizer.Data()...)
			}
		}
	}

	f.Condition = condition

	// Decode multisig closure
	subScript := tokenizer.Script()[tokenizer.ByteIndex():]
	valid, err := f.CSVMultisigClosure.Decode(subScript)
	if err != nil || !valid {
		return false, err
	}

	// Verify the script matches what we would generate
	rebuilt, err := f.Script()
	if err != nil {
		return false, err
	}

	return bytes.Equal(rebuilt, script), nil
}

func (f *ConditionCSVMultisigClosure) Witness(controlBlock []byte, args map[string][]byte) (wire.TxWitness, error) {
	script, err := f.Script()
	if err != nil {
		return nil, fmt.Errorf("failed to generate script: %w", err)
	}

	// Read and execute condition witness
	condWitness, err := ReadTxWitness(args[ConditionWitnessKey])
	if err != nil {
		return nil, fmt.Errorf("failed to read condition witness: %w", err)
	}

	returnValue, err := ExecuteBoolScript(f.Condition, condWitness)
	if err != nil {
		return nil, fmt.Errorf("failed to execute condition: %w", err)
	}

	if !returnValue {
		return nil, fmt.Errorf("condition evaluated to false")
	}

	// Get multisig witness
	multisigWitness, err := f.CSVMultisigClosure.Witness(controlBlock, args)
	if err != nil {
		return nil, err
	}

	multisigWitness = multisigWitness[:len(multisigWitness)-2] // remove control block and script
	witness := append(multisigWitness, condWitness...)
	witness = append(witness, script)
	witness = append(witness, controlBlock)

	return witness, nil
}
