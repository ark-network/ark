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

// TaprootTree is an interface wrapping the methods needed to spend a vtxo taproot contract
// the implementation depends on the chain (liquid or bitcoin)
type TaprootTree interface {
	GetLeaves() []chainhash.Hash
	GetTaprootMerkleProof(leafhash chainhash.Hash) (*TaprootMerkleProof, error)
	GetRoot() chainhash.Hash
}

/*
A vtxo script is defined as a taproot contract with at least 1 forfeit closure (User && ASP) and 1 exit closure (A after t).
It may also contain others closures implementing specific use cases.

VtxoScript abstracts the taproot complexity behind vtxo contracts.
it is compiled, transferred and parsed using descriptor string.

default vtxo script = tr(_,{ and(pk(USER), pk(ASP)), and(older(T), pk(USER)) })
reversible vtxo script = tr(_,{ { and(pk(SENDER), pk(ASP)), and(older(T), pk(SENDER)) }, { and(pk(RECEIVER), pk(ASP) } })
*/
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
