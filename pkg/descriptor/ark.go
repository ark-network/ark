package descriptor

import (
	"encoding/hex"
	"errors"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

const BoardingDescriptorTemplate = "tr(%s,{ and(pk(%s), pk(%s)), and(older(%d), pk(%s)) })"

func ParseBoardingDescriptor(desc TaprootDescriptor) (user *secp256k1.PublicKey, timeout uint, err error) {
	for _, leaf := range desc.ScriptTree {
		if andLeaf, ok := leaf.(*And); ok {
			if first, ok := andLeaf.First.(*Older); ok {
				timeout = first.Timeout
			}

			if second, ok := andLeaf.Second.(*PK); ok {
				keyBytes, err := hex.DecodeString(second.Key.Hex)
				if err != nil {
					return nil, 0, err
				}

				user, err = schnorr.ParsePubKey(keyBytes)
				if err != nil {
					return nil, 0, err
				}
			}
		}
	}

	if user == nil {
		return nil, 0, errors.New("boarding descriptor is invalid")
	}

	if timeout == 0 {
		return nil, 0, errors.New("boarding descriptor is invalid")
	}

	return
}
