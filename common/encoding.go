package common

import (
	"bytes"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/btcsuite/btcd/txscript"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// Address represents an Ark address with HRP, ASP public key, and VTXO Taproot public key
type Address struct {
	HRP        string
	Asp        *secp256k1.PublicKey
	VtxoTapKey *secp256k1.PublicKey
}

// Script generates the output script for the address, this script is used in the VTXO tree leaves
func (a *Address) Script() []byte {
	return append(
		[]byte{
			txscript.OP_1,
			txscript.OP_DATA_32,
		},
		schnorr.SerializePubKey(a.VtxoTapKey)...,
	)
}

// Encode converts the address to its bech32m string representation
func (a *Address) Encode() (string, error) {
	if a.Asp == nil {
		return "", fmt.Errorf("missing asp public key")
	}
	if a.VtxoTapKey == nil {
		return "", fmt.Errorf("missing vtxo tap public key")
	}

	combinedKey := append(
		a.Asp.SerializeCompressed(), a.VtxoTapKey.SerializeCompressed()...,
	)
	grp, err := bech32.ConvertBits(combinedKey, 8, 5, true)
	if err != nil {
		return "", err
	}
	return bech32.EncodeM(a.HRP, grp)
}

// Verify checks if the address matches the given VTXO script
func (a *Address) Verify(vtxoScript VtxoScript[TaprootTree]) (bool, error) {
	tapKey, _, err := vtxoScript.TapTree()
	if err != nil {
		return false, err
	}

	return bytes.Equal(schnorr.SerializePubKey(tapKey), schnorr.SerializePubKey(a.VtxoTapKey)), nil
}

// DecodeAddress parses a bech32m encoded address string and returns an Address object
func DecodeAddress(addr string) (*Address, error) {
	if len(addr) == 0 {
		return nil, fmt.Errorf("address is empty")
	}

	prefix, buf, err := bech32.DecodeNoLimit(addr)
	if err != nil {
		return nil, err
	}
	if prefix != Liquid.Addr && prefix != LiquidTestNet.Addr && prefix != LiquidRegTest.Addr {
		return nil, fmt.Errorf("invalid prefix")
	}
	grp, err := bech32.ConvertBits(buf, 5, 8, false)
	if err != nil {
		return nil, err
	}

	aKey, err := secp256k1.ParsePubKey(grp[:33])
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %s", err)
	}

	vtxoKey, err := secp256k1.ParsePubKey(grp[33:])
	if err != nil {
		return nil, fmt.Errorf("failed to parse asp public key: %s", err)
	}

	return &Address{
		HRP:        prefix,
		Asp:        aKey,
		VtxoTapKey: vtxoKey,
	}, nil
}
