package common

import (
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/vulpemventures/go-elements/taproot"
)

func checksigScript(pubkey *secp256k1.PublicKey) ([]byte, error) {
	key := schnorr.SerializePubKey(pubkey)
	return txscript.NewScriptBuilder().AddData(key).AddOp(txscript.OP_CHECKSIG).Script()
}

func VtxoScript(pubkey *secp256k1.PublicKey) (*taproot.TapElementsLeaf, error) {
	script, err := checksigScript(pubkey)
	if err != nil {
		return nil, err
	}

	tapLeaf := taproot.NewBaseTapElementsLeaf(script)
	return &tapLeaf, nil
}
