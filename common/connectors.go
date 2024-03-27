package common

import (
	"fmt"

	"github.com/vulpemventures/go-elements/elementsutil"
	"github.com/vulpemventures/go-elements/psetv2"
)

func ValidateConnectors(poolTx string, connectors []string) error {
	ptx, err := psetv2.NewPsetFromBase64(poolTx)
	if err != nil {
		return fmt.Errorf("invalid pool tx: %s", err)
	}
	utx, err := ptx.UnsignedTx()
	if err != nil {
		return fmt.Errorf("invalid pool tx: %s", err)
	}
	prevConnectorTxid := utx.TxHash().String()
	prevConnectorVout := uint32(1)
	for i, tx := range connectors {
		ctx, err := psetv2.NewPsetFromBase64(tx)
		if err != nil {
			return fmt.Errorf("invalid connector tx #%d: %s", i, err)
		}
		utx, err := ctx.UnsignedTx()
		if err != nil {
			return fmt.Errorf("invalid connector tx #%d: %s", i, err)
		}
		if ctx.Global.InputCount != 1 {
			return fmt.Errorf(
				"invalid connector tx #%d: got %d inputs, expected 1",
				i, ctx.Global.InputCount,
			)
		}
		inTxid := elementsutil.TxIDFromBytes(ctx.Inputs[0].PreviousTxid)
		inVout := ctx.Inputs[0].PreviousTxIndex
		if inTxid != prevConnectorTxid || (inVout != prevConnectorVout && inVout != 0) {
			return fmt.Errorf(
				"invalid connector tx #%d: got prevout %s:%d, expected %s:%d",
				i, inTxid, inVout, prevConnectorTxid, prevConnectorVout,
			)
		}

		prevConnectorTxid = utx.TxHash().String()
		prevConnectorVout = 0
	}
	return nil
}
