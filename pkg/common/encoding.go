package common

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

const (
	ProtoKey = "ark"
	RelayKey = "relays"
	RelaySep = "-"
)

func EncodeSecKey(hrp string, key *secp256k1.PrivateKey) (string, error) {
	if key == nil {
		return "", fmt.Errorf("missing secret key")
	}
	if hrp != MainNet.SecKey && hrp != TestNet.SecKey {
		return "", fmt.Errorf("invalid prefix")
	}
	grp, err := bech32.ConvertBits(key.Serialize(), 8, 5, true)
	if err != nil {
		return "", err
	}
	return bech32.EncodeM(hrp, grp)
}

func DecodeSecKey(key string) (string, *secp256k1.PrivateKey, error) {
	hrp, buf, err := bech32.DecodeNoLimit(key)
	if err != nil {
		return "", nil, fmt.Errorf("invalid secret key: %s", err)
	}
	if hrp != MainNet.SecKey && hrp != TestNet.SecKey {
		return "", nil, fmt.Errorf("invalid prefix")
	}
	grp, err := bech32.ConvertBits(buf, 5, 8, false)
	if err != nil {
		return "", nil, err
	}
	return hrp, secp256k1.PrivKeyFromBytes(grp), nil
}

func EncodePubKey(hrp string, key *secp256k1.PublicKey) (string, error) {
	if key == nil {
		return "", fmt.Errorf("missing public key")
	}
	if hrp != MainNet.PubKey && hrp != TestNet.PubKey {
		return "", fmt.Errorf("invalid prefix")
	}
	grp, err := bech32.ConvertBits(key.SerializeCompressed(), 8, 5, true)
	if err != nil {
		return "", err
	}
	return bech32.EncodeM(hrp, grp)
}

func DecodePubKey(key string) (string, *secp256k1.PublicKey, error) {
	hrp, buf, err := bech32.DecodeNoLimit(key)
	if err != nil {
		return "", nil, err
	}
	if hrp != MainNet.PubKey && hrp != TestNet.PubKey {
		return "", nil, fmt.Errorf("invalid prefix")
	}
	grp, err := bech32.ConvertBits(buf, 5, 8, false)
	if err != nil {
		return "", nil, err
	}
	if len(grp) < 32 {
		return "", nil, fmt.Errorf("invalid public key length")
	}
	pubkey, err := secp256k1.ParsePubKey(grp)
	if err != nil {
		return "", nil, err
	}
	return hrp, pubkey, nil
}

func EncodeAddress(hrp string, userKey, aspKey *secp256k1.PublicKey) (string, error) {
	if userKey == nil {
		return "", fmt.Errorf("missing public key")
	}
	if aspKey == nil {
		return "", fmt.Errorf("missing asp public key")
	}
	if hrp != MainNet.Addr && hrp != TestNet.Addr {
		return "", fmt.Errorf("invalid prefix")
	}
	combinedKey := append(aspKey.SerializeCompressed(), userKey.SerializeCompressed()...)
	grp, err := bech32.ConvertBits(combinedKey, 8, 5, true)
	if err != nil {
		return "", err
	}
	return bech32.EncodeM(hrp, grp)
}

func DecodeAddress(addr string) (string, *secp256k1.PublicKey, *secp256k1.PublicKey, error) {
	hrp, buf, err := bech32.DecodeNoLimit(addr)
	if err != nil {
		return "", nil, nil, err
	}
	if hrp != MainNet.Addr && hrp != TestNet.Addr {
		return "", nil, nil, fmt.Errorf("invalid prefix")
	}
	grp, err := bech32.ConvertBits(buf, 5, 8, false)
	if err != nil {
		return "", nil, nil, err
	}
	aspKey, err := secp256k1.ParsePubKey(grp[:33])
	if err != nil {
		return "", nil, nil, fmt.Errorf("failed to parse public key: %s", err)
	}
	userKey, err := secp256k1.ParsePubKey(grp[33:])
	if err != nil {
		return "", nil, nil, fmt.Errorf("failed to parse asp public key: %s", err)
	}
	return hrp, userKey, aspKey, nil
}

func EncodeRelayKey(hrp string, key *secp256k1.PublicKey) (string, error) {
	if key == nil {
		return "", fmt.Errorf("missing relay key")
	}
	if hrp != MainNet.RelayKey && hrp != TestNet.RelayKey {
		return "", fmt.Errorf("invalid prefix")
	}
	grp, err := bech32.ConvertBits(key.SerializeCompressed(), 8, 5, true)
	if err != nil {
		return "", err
	}
	return bech32.EncodeM(hrp, grp)
}

func DecodeRelayKey(key string) (string, *secp256k1.PublicKey, error) {
	hrp, buf, err := bech32.DecodeNoLimit(key)
	if err != nil {
		return "", nil, err
	}
	if hrp != MainNet.RelayKey && hrp != TestNet.RelayKey {
		return "", nil, fmt.Errorf("invalid prefix")
	}
	grp, err := bech32.ConvertBits(buf, 5, 8, false)
	if err != nil {
		return "", nil, err
	}
	if len(grp) < 32 {
		return "", nil, fmt.Errorf("invalid public key length")
	}
	pubkey, err := secp256k1.ParsePubKey(grp)
	if err != nil {
		return "", nil, err
	}
	return hrp, pubkey, nil
}

func EncodeUrl(pubkey string, relays ...string) (string, error) {
	if _, _, err := DecodePubKey(pubkey); err != nil {
		return "", fmt.Errorf("invalid public key: %s", err)
	}
	for _, r := range relays {
		if _, _, err := DecodeRelayKey(r); err != nil {
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
	if _, _, err := DecodePubKey(u.Host); err != nil {
		return "", nil, fmt.Errorf("invalid public key: %s", err)
	}
	relays := strings.Split(u.Query().Get(RelayKey), RelaySep)
	for _, r := range relays {
		if _, _, err := DecodeRelayKey(r); err != nil {
			return "", nil, fmt.Errorf("invalid relay public key: %s", err)
		}
	}
	return u.Host, relays, nil
}
