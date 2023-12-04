package handlers

import (
	"encoding/hex"
	"fmt"

	"github.com/ark-network/ark/common"
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

func parseAddress(addr string) (string, error) {
	if len(addr) <= 0 {
		return "", fmt.Errorf("missing address")
	}
	_, userPubkey, _, err := common.DecodeAddress(addr)
	if err != nil {
		return "", fmt.Errorf("invalid address: %s", err)
	}
	pubkey := hex.EncodeToString(userPubkey.SerializeCompressed())
	return pubkey, nil
}
