package bitcointree

import (
	"github.com/ark-network/ark/common/tree"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
)

func aggregateKeys(
	pubkeys []*btcec.PublicKey,
	scriptRoot []byte,
) (*musig2.AggregateKey, error) {
	key, _, _, err := musig2.AggregateKeys(pubkeys, true,
		musig2.WithTaprootKeyTweak(scriptRoot),
	)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func signTree(
	unsigned tree.CongestionTree,
	signingKey *btcec.PrivateKey,
	aggregatedNonce []byte,
) (tree.CongestionTree, error) {
	musig2.NewContext()

	// sign all the inputs of the tree (musig2 sign)
	panic("not implemented")
}

func validateTreeSignature() {
	// validate the signature of the tree (musig2 verify)
	panic("not implemented")
}
