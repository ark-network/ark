/*
* This package contains intermediary events that are used only by the covenantless version
* they let to sign the vtxo tree using musig2 algorithm
* they are not included in domain because they don't mutate the Round state and should not be persisted
 */
package application

import (
	"bytes"
	"encoding/hex"

	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/server/internal/core/domain"
)

// signer should react to this event by generating a musig2 nonce for each transaction in the tree
type RoundSigningStarted struct {
	Id               string
	UnsignedRoundTx  string
	CosignersPubkeys []string
}

// signer should react to this event by partially signing the vtxo tree transactions
// then, delete its ephemeral key
type RoundSigningNoncesGenerated struct {
	Id     string
	Nonces tree.TreeNonces // aggregated nonces
}

func (e RoundSigningNoncesGenerated) SerializeNonces() (string, error) {
	var serialized bytes.Buffer

	if err := e.Nonces.Encode(&serialized); err != nil {
		return "", err
	}

	return hex.EncodeToString(serialized.Bytes()), nil
}

type BatchTree struct {
	ID         string
	Topic      []string
	BatchIndex int32
	Node       tree.Node
}

// implement domain.RoundEvent interface
func (r RoundSigningStarted) GetTopic() string         { return domain.RoundTopic }
func (r RoundSigningNoncesGenerated) GetTopic() string { return domain.RoundTopic }
func (r BatchTree) GetTopic() string                   { return domain.RoundTopic }
