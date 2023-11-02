package sdk

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"

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

type Stakeholder struct {
	Leaves []taproot.TapElementsLeaf
	Amount uint32
}

type SharedTaprootScript struct {
	StakeHolders []Stakeholder
	CommonLeaves []taproot.TapElementsLeaf
	InternalKey  *secp256k1.PublicKey
	Tree         *taproot.IndexedElementsTapScriptTree
}

type ChangeOutputRequirements struct {
	ScriptPubKey []byte
	Amount       uint32
}

func withChangeOutput(taprootWitnessProgram []byte, amount uint32) []byte {
	amountBuffer := make([]byte, 8)
	binary.LittleEndian.PutUint32(amountBuffer, amount)

	script := []byte{
		OP_PUSHCURRENTINPUTINDEX,
		OP_INSPECTOUTPUTSCRIPTPUBKEY,
		txscript.OP_1,
		txscript.OP_EQUALVERIFY,
		txscript.OP_DATA_32,
	}
	script = append(script, taprootWitnessProgram...)
	script = append(script, []byte{
		txscript.OP_EQUALVERIFY,
		OP_PUSHCURRENTINPUTINDEX,
		OP_INSPECTOUTPUTVALUE,
		txscript.OP_1,
		txscript.OP_EQUALVERIFY,
		txscript.OP_DATA_8,
	}...)
	script = append(script, amountBuffer...)
	script = append(script, []byte{
		txscript.OP_EQUALVERIFY,
	}...)

	return script
}

func extractWithChangeOutput(script []byte) (*ChangeOutputRequirements, error) {
	if script[0] != OP_PUSHCURRENTINPUTINDEX {
		return nil, errors.New("invalid taproot script prefix, expected OP_PUSHCURRENTINPUTINDEX, got " + hex.EncodeToString(script[0:1]))
	}

	if script[1] != OP_INSPECTOUTPUTSCRIPTPUBKEY {
		return nil, errors.New("invalid taproot script prefix, expected OP_INSPECTOUTPUTSCRIPTPUBKEY, got " + hex.EncodeToString(script[1:2]))
	}

	if script[2] != txscript.OP_1 {
		return nil, errors.New("invalid taproot script prefix, expected OP_1, got " + hex.EncodeToString(script[2:3]))
	}

	if script[3] != txscript.OP_EQUALVERIFY {
		return nil, errors.New("invalid taproot script prefix, expected OP_EQUALVERIFY, got " + hex.EncodeToString(script[3:4]))
	}

	if script[4] != txscript.OP_DATA_32 {
		return nil, errors.New("invalid taproot script prefix, expected OP_DATA_32, got " + hex.EncodeToString(script[4:5]))
	}

	witnessProgram := script[5:37]

	if script[37] != txscript.OP_EQUALVERIFY {
		return nil, errors.New("invalid taproot script suffix, expected OP_EQUALVERIFY, got " + hex.EncodeToString(script[37:38]))
	}

	if script[38] != OP_PUSHCURRENTINPUTINDEX {
		return nil, errors.New("invalid taproot script suffix, expected OP_PUSHCURRENTINPUTINDEX, got " + hex.EncodeToString(script[38:39]))
	}

	if script[39] != OP_INSPECTOUTPUTVALUE {
		return nil, errors.New("invalid taproot script suffix, expected OP_INSPECTOUTPUTVALUE, got " + hex.EncodeToString(script[39:40]))
	}

	if script[40] != txscript.OP_1 {
		return nil, errors.New("invalid taproot script suffix, expected OP_1, got " + hex.EncodeToString(script[40:41]))
	}

	if script[41] != txscript.OP_EQUALVERIFY {
		return nil, errors.New("invalid taproot script suffix, expected OP_EQUALVERIFY, got " + hex.EncodeToString(script[41:42]))
	}

	if script[42] != txscript.OP_DATA_8 {
		return nil, errors.New("invalid taproot script suffix, expected OP_DATA_8, got " + hex.EncodeToString(script[42:43]))
	}

	amountBuffer := script[43:51]
	amount := binary.LittleEndian.Uint32(amountBuffer)

	if script[51] != txscript.OP_EQUALVERIFY {
		return nil, errors.New("invalid taproot script suffix, expected OP_EQUALVERIFY, got " + hex.EncodeToString(script[49:50]))
	}

	return &ChangeOutputRequirements{
		ScriptPubKey: append([]byte{0x51, 0x20}, witnessProgram...),
		Amount:       amount,
	}, nil
}

func withOutputCheck(taprootWitnessProgram []byte, amount uint32) func(taproot.TapElementsLeaf) taproot.TapElementsLeaf {
	prefix := withChangeOutput(taprootWitnessProgram, amount)
	return func(leaf taproot.TapElementsLeaf) taproot.TapElementsLeaf {

		return taproot.NewBaseTapElementsLeaf(
			append(prefix, leaf.Script...),
		)
	}
}

func createSharedTaprootTree(stakeholders []Stakeholder, commonLeaves []taproot.TapElementsLeaf, internalPubKey *secp256k1.PublicKey) (*taproot.IndexedElementsTapScriptTree, error) {
	if len(stakeholders) == 1 {
		leaves := append(stakeholders[0].Leaves, commonLeaves...)
		return taproot.AssembleTaprootScriptTree(leaves...), nil
	}

	if len(stakeholders) > 1 {
		sharedAmount := uint32(0)
		for _, s := range stakeholders {
			sharedAmount += s.Amount
		}

		leaves := []taproot.TapElementsLeaf{}

		for index, stakeholder := range stakeholders {
			stakeHoldersWithoutCurrent := []Stakeholder{}
			for i, s := range stakeholders {
				if i != index {
					stakeHoldersWithoutCurrent = append(stakeHoldersWithoutCurrent, s)
				}
			}

			changeTree, err := createSharedTaprootTree(stakeHoldersWithoutCurrent, commonLeaves, internalPubKey)
			if err != nil {
				return nil, err
			}

			changeRoot := changeTree.RootNode.TapHash()
			changeWitnessProgram := schnorr.SerializePubKey(taproot.ComputeTaprootOutputKey(internalPubKey, changeRoot[:]))

			leafModifier := withOutputCheck(changeWitnessProgram, sharedAmount-stakeholder.Amount)

			for _, l := range stakeholder.Leaves {
				leaves = append(leaves, leafModifier(l))
			}

			leaves = append(leaves, commonLeaves...)
		}

		return taproot.AssembleTaprootScriptTree(leaves...), nil
	}

	return nil, errors.New("no stakeholders provided")
}

func scriptContainsLeaf(script []byte, leaf taproot.TapElementsLeaf) bool {
	return bytes.Contains(script, leaf.Script)
}

// NewSharedTaprootScript returns a new SharedTaprootScript
func NewSharedTaprootScript(stakeholders []Stakeholder, commonLeaves []taproot.TapElementsLeaf, internalPubKey *secp256k1.PublicKey) (*SharedTaprootScript, error) {
	tree, err := createSharedTaprootTree(stakeholders, commonLeaves, internalPubKey)
	if err != nil {
		return nil, err
	}

	return &SharedTaprootScript{
		StakeHolders: stakeholders,
		CommonLeaves: commonLeaves,
		InternalKey:  internalPubKey,
		Tree:         tree,
	}, nil
}

// TaprootKey returns the taproot witness program key of the shared taproot script
func (s *SharedTaprootScript) TaprootOutputKey() *secp256k1.PublicKey {
	root := s.Tree.RootNode.TapHash()
	return taproot.ComputeTaprootOutputKey(s.InternalKey, root[:])
}

// ScriptPubKey serializes the shared taproot script into a segwit v1 script
func (s *SharedTaprootScript) ScriptPubKey() []byte {
	outputKey := schnorr.SerializePubKey(s.TaprootOutputKey())
	return append([]byte{0x51, 0x20}, outputKey...)
}

// NextSharedTaprootScript returns a new SharedTaprootScript with the spent leaf removed
// spendLeafScript is the one spending the previous shared script, may be found in the input witness
func (s *SharedTaprootScript) NextSharedTaprootScript(spentLeafScript []byte) (*SharedTaprootScript, error) {
	var newStakeholders []Stakeholder

	for _, stakeholder := range s.StakeHolders {
		hasSpentLeaf := false
		for _, leaf := range stakeholder.Leaves {
			if scriptContainsLeaf(spentLeafScript, leaf) {
				hasSpentLeaf = true
				break
			}
		}

		if !hasSpentLeaf {
			newStakeholders = append(newStakeholders, stakeholder)
		}
	}

	if len(newStakeholders) == len(s.StakeHolders) {
		return nil, errors.New("spent leaf script not found")
	}

	newTree, err := createSharedTaprootTree(newStakeholders, s.CommonLeaves, s.InternalKey)
	if err != nil {
		return nil, err
	}

	return &SharedTaprootScript{
		StakeHolders: newStakeholders,
		CommonLeaves: s.CommonLeaves,
		InternalKey:  s.InternalKey,
		Tree:         newTree,
	}, nil
}

func (s *SharedTaprootScript) findLeafByStakeholderScript(script []byte) (*taproot.TapscriptElementsProof, error) {
	// iterate over the leaves of the tree and find the one that contains the script
	for _, leafProof := range s.Tree.LeafMerkleProofs {
		if bytes.Contains(leafProof.Script, script) {
			return &leafProof, nil
		}
	}

	return nil, errors.New("leaf not found in taproot tree")
}

// Requirements finds the tapscript inclusiong proof to spend the leaf script given as argument, it also extract the change output specification required by the leaf
func (s *SharedTaprootScript) Requirements(leafScript []byte) (*ChangeOutputRequirements, *taproot.TapscriptElementsProof, error) {
	leafProof, err := s.findLeafByStakeholderScript(leafScript)
	if err != nil {
		return nil, nil, err
	}

	if bytes.Equal(leafProof.Script, leafScript) {
		return nil, leafProof, nil
	}

	changeRequirements, err := extractWithChangeOutput(leafProof.Script)
	if err != nil {
		return nil, nil, err
	}

	return changeRequirements, leafProof, nil
}
