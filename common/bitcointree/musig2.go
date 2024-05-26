package bitcointree

import (
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
