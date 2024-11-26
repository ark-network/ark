package descriptor

import (
	"encoding/hex"
	"errors"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// tr(unspendable, { and(pk(user), pk(server)), and(older(timeout), pk(user)) })
const DefaultVtxoDescriptorTemplate = "tr(%s,{ and(pk(%s), pk(%s)), and(older(%d), pk(%s)) })"

func ParseDefaultVtxoDescriptor(
	descriptor string,
) (user, server *secp256k1.PublicKey, timeout uint, err error) {
	desc, err := ParseTaprootDescriptor(descriptor)
	if err != nil {
		return nil, nil, 0, err
	}

	if len(desc.ScriptTree) != 2 {
		return nil, nil, 0, errors.New("not a default vtxo script descriptor")
	}

	for _, leaf := range desc.ScriptTree {
		if andLeaf, ok := leaf.(*And); ok {
			if first, ok := andLeaf.First.(*PK); ok {
				if second, ok := andLeaf.Second.(*PK); ok {
					keyBytes, err := hex.DecodeString(first.Key.Hex)
					if err != nil {
						return nil, nil, 0, err
					}

					user, err = schnorr.ParsePubKey(keyBytes)
					if err != nil {
						return nil, nil, 0, err
					}

					keyBytes, err = hex.DecodeString(second.Key.Hex)
					if err != nil {
						return nil, nil, 0, err
					}

					server, err = schnorr.ParsePubKey(keyBytes)
					if err != nil {
						return nil, nil, 0, err
					}
				}
			}

			if first, ok := andLeaf.First.(*Older); ok {
				if second, ok := andLeaf.Second.(*PK); ok {
					timeout = first.Timeout
					keyBytes, err := hex.DecodeString(second.Key.Hex)
					if err != nil {
						return nil, nil, 0, err
					}

					user, err = schnorr.ParsePubKey(keyBytes)
					if err != nil {
						return nil, nil, 0, err
					}
				}
			}
		}
	}

	if user == nil {
		return nil, nil, 0, errors.New("boarding descriptor is invalid")
	}

	if server == nil {
		return nil, nil, 0, errors.New("boarding descriptor is invalid")
	}

	if timeout == 0 {
		return nil, nil, 0, errors.New("boarding descriptor is invalid")
	}

	return
}
