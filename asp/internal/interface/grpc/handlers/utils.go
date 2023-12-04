package handlers

import (
	"fmt"

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
