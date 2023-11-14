package common

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

const (
	PubKeyPrefix  = "arkpub"
	SecKeyPrefix  = "arksec"
	AddressPrefix = "arkaddr"
	RelayPrefix   = "arkrelay"
	ProtoKey      = "ark"
	RelayKey      = "relays"
	RelaySep      = "-"
)

func EncodeSecKey(key *secp256k1.PrivateKey) (string, error) {
	if key == nil {
		return "", fmt.Errorf("missing secret key")
	}
	grp, err := bech32.ConvertBits(key.Serialize(), 8, 5, true)
	if err != nil {
		return "", err
	}
	return bech32.Encode(SecKeyPrefix, grp)
}

func DecodeSecKey(key string) (*secp256k1.PrivateKey, error) {
	hrp, buf, err := bech32.DecodeNoLimit(key)
	if err != nil {
		return nil, fmt.Errorf("invalid secret key: %s", err)
	}
	if hrp != SecKeyPrefix {
		return nil, fmt.Errorf("invalid prefix")
	}
	grp, err := bech32.ConvertBits(buf, 5, 8, false)
	if err != nil {
		return nil, err
	}
	return secp256k1.PrivKeyFromBytes(grp), nil
}

func EncodePubKey(key *secp256k1.PublicKey) (string, error) {
	if key == nil {
		return "", fmt.Errorf("missing public key")
	}
	grp, err := bech32.ConvertBits(key.SerializeCompressed(), 8, 5, true)
	if err != nil {
		return "", err
	}
	return bech32.Encode(PubKeyPrefix, grp)
}

func DecodePubKey(key string) (*secp256k1.PublicKey, error) {
	hrp, buf, err := bech32.DecodeNoLimit(key)
	if err != nil {
		return nil, err
	}
	if hrp != PubKeyPrefix {
		return nil, fmt.Errorf("invalid prefix")
	}
	grp, err := bech32.ConvertBits(buf, 5, 8, false)
	if err != nil {
		return nil, err
	}
	if len(grp) < 32 {
		return nil, fmt.Errorf("invalid public key length")
	}
	return secp256k1.ParsePubKey(grp)
}

func EncodeAddress(key *secp256k1.PublicKey) (string, error) {
	if key == nil {
		return "", fmt.Errorf("missing public key")
	}
	grp, err := bech32.ConvertBits(key.SerializeCompressed(), 8, 5, true)
	if err != nil {
		return "", err
	}
	return bech32.Encode(AddressPrefix, grp)
}

func DecodeAddress(addr string) (*secp256k1.PublicKey, error) {
	hrp, buf, err := bech32.Decode(addr)
	if err != nil {
		return nil, err
	}
	if hrp != AddressPrefix {
		return nil, fmt.Errorf("invalid prefix")
	}
	grp, err := bech32.ConvertBits(buf, 5, 8, false)
	if err != nil {
		return nil, err
	}
	return secp256k1.ParsePubKey(grp)
}

func EncodeRelayKey(key *secp256k1.PublicKey) (string, error) {
	if key == nil {
		return "", fmt.Errorf("missing relay key")
	}
	grp, err := bech32.ConvertBits(key.SerializeCompressed(), 8, 5, true)
	if err != nil {
		return "", err
	}
	return bech32.Encode(RelayPrefix, grp)
}

func DecodeRelayKey(key string) (*secp256k1.PublicKey, error) {
	hrp, buf, err := bech32.DecodeNoLimit(key)
	if err != nil {
		return nil, err
	}
	if hrp != RelayPrefix {
		return nil, fmt.Errorf("invalid prefix")
	}
	grp, err := bech32.ConvertBits(buf, 5, 8, false)
	if err != nil {
		return nil, err
	}
	if len(grp) < 32 {
		return nil, fmt.Errorf("invalid public key length")
	}
	return secp256k1.ParsePubKey(grp)
}

func EncodeUrl(pubkey string, relays ...string) (string, error) {
	if _, err := DecodePubKey(pubkey); err != nil {
		return "", fmt.Errorf("invalid public key: %s", err)
	}
	for _, r := range relays {
		if _, err := DecodeRelayKey(r); err != nil {
			return "", fmt.Errorf("invalid relay public key: %s", err)
		}
	}
	u := url.URL{Scheme: ProtoKey, Host: pubkey}
	q := u.Query()
	if len(relays) > 0 {
		q.Add(RelayKey, strings.Join(relays, RelaySep))
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func DecodeUrl(arkurl string) (string, []string, error) {
	u, err := url.Parse(arkurl)
	if err != nil {
		return "", nil, err
	}
	if u.Scheme != ProtoKey {
		return "", nil, fmt.Errorf("invalid proto")
	}
	if _, err := DecodePubKey(u.Host); err != nil {
		return "", nil, fmt.Errorf("invalid public key: %s", err)
	}
	relays := strings.Split(u.Query().Get(RelayKey), RelaySep)
	for _, r := range relays {
		if _, err := DecodeRelayKey(r); err != nil {
			return "", nil, fmt.Errorf("invalid relay public key: %s", err)
		}
	}
	return u.Host, relays, nil
}
