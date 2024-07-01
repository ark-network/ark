package common

import (
	"fmt"

	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func EncodeAddress(
	hrp string, userKey, aspKey *secp256k1.PublicKey,
) (addr string, err error) {
	if userKey == nil {
		err = fmt.Errorf("missing public key")
		return
	}
	if aspKey == nil {
		err = fmt.Errorf("missing asp public key")
		return
	}
	if hrp != Liquid.Addr && hrp != LiquidTestNet.Addr {
		err = fmt.Errorf("invalid prefix")
		return
	}
	combinedKey := append(
		aspKey.SerializeCompressed(), userKey.SerializeCompressed()...,
	)
	grp, err := bech32.ConvertBits(combinedKey, 8, 5, true)
	if err != nil {
		return
	}
	addr, err = bech32.EncodeM(hrp, grp)
	return
}

func DecodeAddress(
	addr string,
) (hrp string, userKey *secp256k1.PublicKey, aspKey *secp256k1.PublicKey, err error) {
	prefix, buf, err := bech32.DecodeNoLimit(addr)
	if err != nil {
		return
	}
	if prefix != Liquid.Addr && prefix != LiquidTestNet.Addr {
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
