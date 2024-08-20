// This package contains intermediary events that are used only by the covenantless version
// they let to sign the congestion tree using musig2 algorithm
// they are not included in the domain as "RoundEvent" because they don't mutate the Round state and should not be persisted
package covenantlessevent

import (
	"bytes"
	"encoding/hex"

	"github.com/ark-network/ark/common/bitcointree"
	"github.com/ark-network/ark/common/tree"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// signer should react to this event by generating a musig2 nonce for each transaction in the tree
type RoundSigningStarted struct {
	Id                     string
	UnsignedCongestionTree tree.CongestionTree
	Cosigners              []*secp256k1.PublicKey
}

// signer should react to this event by partially signing the congestion tree transactions
// then, delete its ephemeral key
type RoundSigningNoncesGenerated struct {
	Id     string
	Nonces bitcointree.TreeNonces // aggregated nonces
}

func (e RoundSigningNoncesGenerated) SerializeNonces() (string, error) {
	var serialized bytes.Buffer

	if err := e.Nonces.Encode(&serialized); err != nil {
		return "", err
	}

	return hex.EncodeToString(serialized.Bytes()), nil
}
