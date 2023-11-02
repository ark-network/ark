package sdk

import (
	"fmt"

	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

const (
	PubKeyPrefix = "arkpub"
	SecKeyPrefix = "arksec"
)

func EncodeSecKey(key *secp256k1.PrivateKey) (string, error) {
	return bech32.Encode(SecKeyPrefix, key.Serialize())
}

func DecodeSecKey(key string) (*secp256k1.PrivateKey, error) {
	prefix, buf, err := bech32.Decode(key)
	if err != nil {
		return nil, err
	}
	if prefix != SecKeyPrefix {
		return nil, fmt.Errorf("invalid prefix")
	}

	return secp256k1.PrivKeyFromBytes(buf), nil
}

func EncodePubKey(key *secp256k1.PublicKey) (string, error) {
	return bech32.Encode(PubKeyPrefix, key.SerializeCompressed())
}

func DecodePubKey(key string) (*secp256k1.PublicKey, error) {
	prefix, buf, err := bech32.Decode(key)
	if err != nil {
		return nil, err
	}
	if prefix != PubKeyPrefix {
		return nil, fmt.Errorf("invalid prefix")
	}

	return secp256k1.ParsePubKey(buf)
}
