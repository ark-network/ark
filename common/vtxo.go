package common

import (
	"errors"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

var (
	ErrLeafNotFound    = errors.New("leaf not found in taproot tree")
	ErrWrongDescriptor = errors.New("wrong descriptor, cannot parse vtxo script")
)

type TaprootMerkleProof struct {
	ControlBlock []byte
	Script       []byte
}

type TaprootTree interface {
	GetTaprootMerkleProof(leafhash chainhash.Hash) (*TaprootMerkleProof, error)
	GetRoot() chainhash.Hash
}

type VtxoScript[T TaprootTree] interface {
	TapTree() (taprootKey *secp256k1.PublicKey, taprootScriptTree T, err error)
	ToDescriptor() string
	FromDescriptor(descriptor string) error
}
