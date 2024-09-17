package common

import (
	"errors"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

var (
	ErrWrongDescriptor = errors.New("wrong descriptor, cannot parse vtxo script")
)

type TaprootMerkleProof struct {
	ControlBlock []byte
	Script       []byte
}

type TaprootTree interface {
	GetLeaves() []chainhash.Hash
	GetTaprootMerkleProof(leafhash chainhash.Hash) (*TaprootMerkleProof, error)
	GetRoot() chainhash.Hash
}

type VtxoScript[T TaprootTree] interface {
	TapTree() (taprootKey *secp256k1.PublicKey, taprootScriptTree T, err error)
	ToDescriptor() string
	FromDescriptor(descriptor string) error
}

// BiggestLeafMerkleProof returns the leaf with the biggest witness size (for fee estimation)
// we need this to estimate the fee without knowning the exact leaf that will be spent
func BiggestLeafMerkleProof(t TaprootTree) (*TaprootMerkleProof, error) {
	var biggest *TaprootMerkleProof
	var biggestSize int

	for _, leaf := range t.GetLeaves() {
		proof, err := t.GetTaprootMerkleProof(leaf)
		if err != nil {
			return nil, err
		}

		if len(proof.ControlBlock)+len(proof.Script) > biggestSize {
			biggest = proof
			biggestSize = len(proof.ControlBlock) + len(proof.Script)
		}
	}

	return biggest, nil
}
