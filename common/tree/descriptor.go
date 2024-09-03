package tree

import (
	"encoding/hex"

	"github.com/ark-network/ark/common/descriptor"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/vulpemventures/go-elements/taproot"
)

func ComputeOutputScript(desc descriptor.TaprootDescriptor) ([]byte, error) {
	leaves := make([]taproot.TapElementsLeaf, 0)

	for _, l := range desc.ScriptTree {
		script, err := l.Script(false)
		if err != nil {
			return nil, err
		}

		scriptBytes, err := hex.DecodeString(script)
		if err != nil {
			return nil, err
		}

		leaves = append(leaves, taproot.NewBaseTapElementsLeaf(scriptBytes))
	}

	taprootTree := taproot.AssembleTaprootScriptTree(
		leaves...,
	)

	root := taprootTree.RootNode.TapHash()

	internalKey, err := hex.DecodeString(desc.InternalKey.Hex)
	if err != nil {
		return nil, err
	}

	internalKeyParsed, err := schnorr.ParsePubKey(internalKey)
	if err != nil {
		return nil, err
	}

	taprootKey := taproot.ComputeTaprootOutputKey(internalKeyParsed, root[:])

	outputScript, err := taprootOutputScript(taprootKey)
	if err != nil {
		return nil, err
	}

	return outputScript, nil
}
