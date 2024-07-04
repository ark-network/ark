package domain

import (
	"github.com/ark-network/ark/internal/core/ports"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type LiquidityProvider struct {
	PubKey  *secp256k1.PublicKey
	UTXO    []ports.TxInput
	FeeRate uint64
}

func (lp *LiquidityProvider) CheckFeeRate(minRate, maxRate uint64) bool {
	return lp.FeeRate >= minRate && lp.FeeRate <= maxRate
}
