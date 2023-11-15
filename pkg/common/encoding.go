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

func EncodeSecKey(hrp string, key *secp256k1.PrivateKey) (seckey string, err error) {
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
	seckey, err = bech32.EncodeM(hrp, grp)
	return
}

func DecodeSecKey(key string) (hrp string, seckey *secp256k1.PrivateKey, err error) {
	prefix, buf, err := bech32.DecodeNoLimit(key)
	if err != nil {
		err = fmt.Errorf("invalid secret key: %s", err)
		return
	}
	if prefix != MainNet.SecKey && prefix != TestNet.SecKey {
		err = fmt.Errorf("invalid prefix")
		return
	}
	grp, err := bech32.ConvertBits(buf, 5, 8, false)
	if err != nil {
		return
	}
	hrp = prefix
	seckey = secp256k1.PrivKeyFromBytes(grp)
	return
}

func EncodePubKey(hrp string, key *secp256k1.PublicKey) (pubkey string, err error) {
	if key == nil {
		err = fmt.Errorf("missing public key")
		return
	}
	if hrp != MainNet.PubKey && hrp != TestNet.PubKey {
		err = fmt.Errorf("invalid prefix")
		return
	}
	grp, err := bech32.ConvertBits(key.SerializeCompressed(), 8, 5, true)
	if err != nil {
		return
	}
	pubkey, err = bech32.EncodeM(hrp, grp)
	return
}

func DecodePubKey(key string) (hrp string, pubkey *secp256k1.PublicKey, err error) {
	prefix, buf, err := bech32.DecodeNoLimit(key)
	if err != nil {
		return
	}
	if prefix != MainNet.PubKey && prefix != TestNet.PubKey {
		err = fmt.Errorf("invalid prefix")
		return
	}
	grp, err := bech32.ConvertBits(buf, 5, 8, false)
	if err != nil {
		return
	}
	if len(grp) < 32 {
		err = fmt.Errorf("invalid public key length")
		return
	}
	pubkey, err = secp256k1.ParsePubKey(grp)
	if err != nil {
		return
	}
	hrp = prefix
	return
}

func EncodeAddress(hrp string, userKey, aspKey *secp256k1.PublicKey) (addr string, err error) {
	if userKey == nil {
		err = fmt.Errorf("missing public key")
		return
	}
	if aspKey == nil {
		err = fmt.Errorf("missing asp public key")
		return
	}
	if hrp != MainNet.Addr && hrp != TestNet.Addr {
		err = fmt.Errorf("invalid prefix")
		return
	}
	combinedKey := append(aspKey.SerializeCompressed(), userKey.SerializeCompressed()...)
	grp, err := bech32.ConvertBits(combinedKey, 8, 5, true)
	if err != nil {
		return
	}
	addr, err = bech32.EncodeM(hrp, grp)
	return
}

func DecodeAddress(addr string) (hrp string, userKey *secp256k1.PublicKey, aspKey *secp256k1.PublicKey, err error) {
	prefix, buf, err := bech32.DecodeNoLimit(addr)
	if err != nil {
		return
	}
	if prefix != MainNet.Addr && prefix != TestNet.Addr {
		err = fmt.Errorf("invalid prefix")
		return
	}
	grp, err := bech32.ConvertBits(buf, 5, 8, false)
	if err != nil {
		return
	}
	aKey, err := secp256k1.ParsePubKey(grp[:33])
	if err != nil {
		err = fmt.Errorf("failed to parse public key: %s", err)
		return
	}
	uKey, err := secp256k1.ParsePubKey(grp[33:])
	if err != nil {
		err = fmt.Errorf("failed to parse asp public key: %s", err)
		return
	}
	hrp = prefix
	userKey = uKey
	aspKey = aKey
	return
}

func EncodeRelayKey(hrp string, key *secp256k1.PublicKey) (pubkey string, err error) {
	if key == nil {
		err = fmt.Errorf("missing relay key")
		return
	}
	if hrp != MainNet.RelayKey && hrp != TestNet.RelayKey {
		err = fmt.Errorf("invalid prefix")
		return
	}
	grp, err := bech32.ConvertBits(key.SerializeCompressed(), 8, 5, true)
	if err != nil {
		return
	}
	pubkey, err = bech32.EncodeM(hrp, grp)
	return
}

func DecodeRelayKey(key string) (hrp string, pubkey *secp256k1.PublicKey, err error) {
	prefix, buf, err := bech32.DecodeNoLimit(key)
	if err != nil {
		return
	}
	if prefix != MainNet.RelayKey && prefix != TestNet.RelayKey {
		err = fmt.Errorf("invalid prefix")
		return
	}
	grp, err := bech32.ConvertBits(buf, 5, 8, false)
	if err != nil {
		return
	}
	if len(grp) < 32 {
		err = fmt.Errorf("invalid public key length")
		return
	}
	pubkey, err = secp256k1.ParsePubKey(grp)
	if err != nil {
		return
	}
	hrp = prefix
	return
}

func EncodeUrl(host string, relays ...string) (arkurl string, err error) {
	_, _, err = DecodePubKey(host)
	if err != nil {
		err = fmt.Errorf("invalid public key: %s", err)
		return
	}
	for _, r := range relays {
		_, _, err = DecodeRelayKey(r)
		if err != nil {
			err = fmt.Errorf("invalid relay public key: %s", err)
			return
		}
	}
	u := url.URL{Scheme: ProtoKey, Host: host}
	q := u.Query()
	if len(relays) > 0 {
		q.Add(RelayKey, strings.Join(relays, RelaySep))
	}
	u.RawQuery = q.Encode()
	arkurl = u.String()
	return
}

func DecodeUrl(arkurl string) (host string, relays []string, err error) {
	u, err := url.Parse(arkurl)
	if err != nil {
		return
	}
	if u.Scheme != ProtoKey {
		err = fmt.Errorf("invalid proto")
		return
	}
	_, _, err = DecodePubKey(u.Host)
	if err != nil {
		err = fmt.Errorf("invalid public key: %s", err)
		return
	}
	list := strings.Split(u.Query().Get(RelayKey), RelaySep)
	for _, r := range list {
		_, _, err = DecodeRelayKey(r)
		if err != nil {
			err = fmt.Errorf("invalid relay public key: %s", err)
			return
		}
	}
	host = u.Host
	relays = make([]string, len(list))
	copy(relays, list)
	return
}
