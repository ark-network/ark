package tree

import (
	"github.com/vulpemventures/go-elements/psetv2"
)

type SigningType uint8

const (
	// SignAll makes the signer sign all the branches
	SignAll SigningType = iota
	// SignBranch makes the signer sign only its own branch
	SignBranch
)

type TreeFactory func(outpoint psetv2.InputArgs) (TxTree, error)

// Leaf is the output leaf of a TxTree
type Leaf struct {
	Script     string
	Amount     uint64
	Musig2Data *Musig2
}

type Musig2 struct {
	CosignersPublicKeys []string
	SigningType         SigningType
}
