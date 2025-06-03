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

// the user should react to this event by confirming the registration using intent_id
type BatchStarted struct {
	domain.RoundEvent
	IntentIdsHashes [][32]byte
	BatchExpiry     uint32
	ForfeitAddress  string
}

// signer should react to this event by generating a musig2 nonce for each transaction in the tree
type RoundSigningStarted struct {
	domain.RoundEvent
	UnsignedRoundTx  string
	CosignersPubkeys []string
}

// signer should react to this event by partially signing the vtxo tree transactions
// then, delete its ephemeral key
type RoundSigningNoncesGenerated struct {
	domain.RoundEvent
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
	domain.RoundEvent
	Topic      []string
	BatchIndex int32
	Node       tree.Node
}

type BatchTreeSignature struct {
	domain.RoundEvent
	Topic      []string
	BatchIndex int32
	Level      int32
	LevelIndex int32
	Signature  string
}

// implement domain.RoundEvent interface
func (r RoundSigningStarted) GetTopic() string         { return domain.RoundTopic }
func (r RoundSigningNoncesGenerated) GetTopic() string { return domain.RoundTopic }
func (r BatchTree) GetTopic() string                   { return domain.RoundTopic }
func (r BatchTreeSignature) GetTopic() string          { return domain.RoundTopic }
