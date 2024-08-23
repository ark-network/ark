package application

import (
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type VtxoInput struct {
	domain.VtxoKey
}

func (i VtxoInput) GetTxid() string {
	return i.Txid
}

func (i VtxoInput) GetIndex() uint32 {
	return i.VOut
}

func (i VtxoInput) IsReverseBoarding() bool {
	return false
}

func (i VtxoInput) GetReverseBoardingPublicKey() *secp256k1.PublicKey {
	return nil
}

type ReverseBoardingInput struct {
	domain.VtxoKey
	OwnerPublicKey *secp256k1.PublicKey
}

func (i ReverseBoardingInput) GetTxid() string {
	return i.Txid
}

func (i ReverseBoardingInput) GetIndex() uint32 {
	return i.VOut
}

func (i ReverseBoardingInput) IsReverseBoarding() bool {
	return true
}

func (i ReverseBoardingInput) GetReverseBoardingPublicKey() *secp256k1.PublicKey {
	return i.OwnerPublicKey
}
