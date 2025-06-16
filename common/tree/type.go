package tree

// Leaf is the output leaf of a TxTree
type Leaf struct {
	Script              string
	Amount              uint64
	CosignersPublicKeys []string
}
