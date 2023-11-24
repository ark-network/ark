package txbuilder

import (
	"github.com/vulpemventures/go-elements/psetv2"
)

func createConnectors(
	poolTxID string,
	connectorOutputIndex uint32,
	connectorOutput psetv2.OutputArgs,
	changeScript []byte,
	numberOfConnectors uint64,
) (connectorsPsets []string, err error) {
	previousInput := psetv2.InputArgs{
		Txid:    poolTxID,
		TxIndex: connectorOutputIndex,
	}

	// compute the initial amount of the connectors output in pool transaction
	remainingAmount := connectorAmount * numberOfConnectors

	connectorsPset := make([]string, 0, numberOfConnectors-1)
	for i := uint64(0); i < numberOfConnectors-1; i++ {
		// create a new pset
		pset, err := psetv2.New(nil, nil, nil)
		if err != nil {
			return nil, err
		}

		updater, err := psetv2.NewUpdater(pset)
		if err != nil {
			return nil, err
		}

		err = updater.AddInputs([]psetv2.InputArgs{previousInput})
		if err != nil {
			return nil, err
		}

		err = updater.AddOutputs([]psetv2.OutputArgs{connectorOutput})
		if err != nil {
			return nil, err
		}

		changeAmount := remainingAmount - connectorOutput.Amount
		if changeAmount > 0 {
			changeOutput := psetv2.OutputArgs{
				Asset:  connectorOutput.Asset,
				Amount: changeAmount,
				Script: changeScript,
			}
			err = updater.AddOutputs([]psetv2.OutputArgs{changeOutput})
			if err != nil {
				return nil, err
			}
			tx, _ := pset.UnsignedTx()
			txid := tx.TxHash().String()

			// make the change the next previousInput
			previousInput = psetv2.InputArgs{
				Txid:    txid,
				TxIndex: 1,
			}
		}

		base64, err := pset.ToBase64()
		if err != nil {
			return nil, err
		}

		connectorsPset = append(connectorsPset, base64)
	}

	return connectorsPset, nil
}
