package tree

import (
	"bytes"
	"encoding/binary"

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

// VtxoScript returns a simple checksig script for a given pubkey
func VtxoScript(pubkey *secp256k1.PublicKey) (*taproot.TapElementsLeaf, error) {
	script, err := checksigScript(pubkey)
	if err != nil {
		return nil, err
	}

	tapLeaf := taproot.NewBaseTapElementsLeaf(script)
	return &tapLeaf, nil
}

// SweepScript returns a taproot leaf letting the owner of the key to spend the output after a given timeDelta
func SweepScript(sweepKey *secp256k1.PublicKey, seconds uint) (*taproot.TapElementsLeaf, error) {
	sweepScript, err := csvChecksigScript(sweepKey, seconds)
	if err != nil {
		return nil, err
	}

	tapLeaf := taproot.NewBaseTapElementsLeaf(sweepScript)
	return &tapLeaf, nil
}

// BranchScript returns a taproot leaf that will split the coin in two outputs
// each output (left and right) will have the given amount and the given taproot key as witness program
func BranchScript(
	leftKey, rightKey *secp256k1.PublicKey, leftAmount, rightAmount uint64,
) taproot.TapElementsLeaf {
	nextScriptLeft := withOutput(txscript.OP_0, schnorr.SerializePubKey(leftKey), leftAmount, rightKey != nil)
	branchScript := append([]byte{}, nextScriptLeft...)
	if rightKey != nil {
		nextScriptRight := withOutput(txscript.OP_1, schnorr.SerializePubKey(rightKey), rightAmount, false)
		branchScript = append(branchScript, nextScriptRight...)
	}
	return taproot.NewBaseTapElementsLeaf(branchScript)
}

func decodeBranchScript(script []byte) (valid bool, leftKey, rightKey *secp256k1.PublicKey, leftAmount, rightAmount uint64, err error) {
	if len(script) != 52 && len(script) != 104 {
		return false, nil, nil, 0, 0, nil
	}

	isLeftOnly := len(script) == 52

	validLeft, leftKey, leftAmount, err := decodeWithOutputScript(script[:52], txscript.OP_0, !isLeftOnly)
	if err != nil {
		return false, nil, nil, 0, 0, err
	}

	if !validLeft {
		return false, nil, nil, 0, 0, nil
	}

	if isLeftOnly {
		return true, leftKey, nil, leftAmount, 0, nil
	}

	validRight, rightKey, rightAmount, err := decodeWithOutputScript(script[52:], txscript.OP_1, false)
	if err != nil {
		return false, nil, nil, 0, 0, err
	}

	if !validRight {
		return false, nil, nil, 0, 0, nil
	}

	rebuilt := BranchScript(leftKey, rightKey, leftAmount, rightAmount)

	if !bytes.Equal(rebuilt.Script, script) {
		return false, nil, nil, 0, 0, nil
	}

	return true, leftKey, rightKey, leftAmount, rightAmount, nil
}

func decodeWithOutputScript(script []byte, expectedIndex byte, isVerify bool) (valid bool, pubkey *secp256k1.PublicKey, amount uint64, err error) {
	if len(script) != 52 {
		return false, nil, 0, nil
	}

	if script[0] != expectedIndex {
		return false, nil, 0, nil
	}

	// 32 bytes for the witness program
	pubkey, err = schnorr.ParsePubKey(script[5 : 5+32])
	if err != nil {
		return false, nil, 0, err
	}

	// verify the index of INSPECTVALUE
	if script[38] != expectedIndex {
		return false, nil, 0, nil
	}

	// 8 bytes for the amount
	amountBytes := script[len(script)-9 : len(script)-1]
	amount = binary.LittleEndian.Uint64(amountBytes)

	rebuilt := withOutput(expectedIndex, schnorr.SerializePubKey(pubkey), amount, isVerify)
	if !bytes.Equal(rebuilt, script) {
		return false, nil, 0, nil
	}

	return true, pubkey, amount, nil
}

func decodeChecksigScript(script []byte) (valid bool, pubkey *secp256k1.PublicKey, err error) {
	data32Index := bytes.Index(script, []byte{txscript.OP_DATA_32})
	if data32Index == -1 {
		return false, nil, nil
	}

	key := script[data32Index+1 : data32Index+33]
	if len(key) != 32 {
		return false, nil, nil
	}

	pubkey, err = schnorr.ParsePubKey(key)
	if err != nil {
		return false, nil, err
	}

	rebuilt, err := checksigScript(pubkey)
	if err != nil {
		return false, nil, err
	}

	if !bytes.Equal(rebuilt, script) {
		return false, nil, nil
	}

	return true, pubkey, nil
}

func DecodeSweepScript(script []byte) (valid bool, aspPubKey *secp256k1.PublicKey, seconds uint, err error) {
	csvIndex := bytes.Index(script, []byte{txscript.OP_CHECKSEQUENCEVERIFY, txscript.OP_DROP})
	if csvIndex == -1 || csvIndex == 0 {
		return false, nil, 0, nil
	}

	sequence := script[1:csvIndex]

	seconds, err = common.BIP68Decode(sequence)
	if err != nil {
		return false, nil, 0, err
	}

	checksigScript := script[csvIndex+2:]
	valid, aspPubKey, err = decodeChecksigScript(checksigScript)
	if err != nil {
		return false, nil, 0, err
	}

	if !valid {
		return false, nil, 0, nil
	}

	rebuilt, err := csvChecksigScript(aspPubKey, seconds)
	if err != nil {
		return false, nil, 0, err
	}

	if !bytes.Equal(rebuilt, script) {
		return false, nil, 0, nil
	}

	return valid, aspPubKey, seconds, nil
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
func csvChecksigScript(pubkey *secp256k1.PublicKey, seconds uint) ([]byte, error) {
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
	return txscript.NewScriptBuilder().AddData(key).AddOp(txscript.OP_CHECKSIG).Script()
}

// withOutput returns an introspection script that checks the script and the amount of the output at the given index
// verify will add an OP_EQUALVERIFY at the end of the script, otherwise it will add an OP_EQUAL
// length = 52 bytes
func withOutput(index byte, taprootWitnessProgram []byte, amount uint64, verify bool) []byte {
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
