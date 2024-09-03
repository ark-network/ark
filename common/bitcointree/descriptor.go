package bitcointree

import (
	"encoding/hex"

	"github.com/ark-network/ark/pkg/descriptor"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
)

func ComputeOutputScript(desc descriptor.TaprootDescriptor) ([]byte, error) {
	leaves := make([]txscript.TapLeaf, 0)
	for _, leaf := range desc.ScriptTree {
		scriptHex, err := leaf.Script(false)
		if err != nil {
			return nil, err
		}

		script, err := hex.DecodeString(scriptHex)
		if err != nil {
			return nil, err
		}

		leaves = append(leaves, txscript.NewBaseTapLeaf(script))
	}

	taprootTree := txscript.AssembleTaprootScriptTree(leaves...)

	root := taprootTree.RootNode.TapHash()
	internalKey, err := hex.DecodeString(desc.InternalKey.Hex)
	if err != nil {
		return nil, err
	}

	internalKeyParsed, err := schnorr.ParsePubKey(internalKey)
	if err != nil {
		return nil, err
	}

	taprootKey := txscript.ComputeTaprootOutputKey(internalKeyParsed, root[:])

	outputScript, err := taprootOutputScript(taprootKey)
	if err != nil {
		return nil, err
	}

	return outputScript, nil
}
