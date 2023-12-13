package handlers

import (
	"fmt"

	"github.com/ark-network/ark/common"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/vulpemventures/go-elements/psetv2"
)

func parseTxs(txs []string) ([]string, error) {
	if len(txs) <= 0 {
		return nil, fmt.Errorf("missing list of forfeit txs")
	}
	for _, tx := range txs {
		if _, err := psetv2.NewPsetFromBase64(tx); err != nil {
			return nil, fmt.Errorf("invalid tx format")
		}
	}
	return txs, nil
}

func parseAddress(addr string) (*secp256k1.PublicKey, error) {
	if len(addr) <= 0 {
		return nil, fmt.Errorf("missing address")
	}
	_, userPubkey, _, err := common.DecodeAddress(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid address: %s", err)
	}
	return userPubkey, nil
}
