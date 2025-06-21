package tree

// Leaf is the output leaf of a TxGraph
type Leaf struct {
	Script              string
	Amount              uint64
	CosignersPublicKeys []string
}
