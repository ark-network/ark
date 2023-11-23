package txbuilder

import (
	"github.com/vulpemventures/go-elements/psetv2"
)

func createConnectors(
	poolTxID string,
	connectorOutputIndex uint32,
	connectorOutput psetv2.OutputArgs,
	feeAmount uint64,
	changeScript []byte,
	numberOfConnectors uint64,
) (connectorsPsets []string, err error) {
	feeOutput := psetv2.OutputArgs{
		Asset:  connectorOutput.Asset,
		Amount: feeAmount,
	}

	previousInput := psetv2.InputArgs{
		Txid:    poolTxID,
		TxIndex: connectorOutputIndex,
	}

	remainingAmount := (connectorOutput.Amount + feeAmount) * numberOfConnectors

	connectorsPset := make([]string, numberOfConnectors, numberOfConnectors)

	for i := uint64(0); i < numberOfConnectors; i++ {
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

		// compute the right change
		changeOutput := psetv2.OutputArgs{
			Asset:  connectorOutput.Asset,
			Amount: remainingAmount - connectorOutput.Amount - feeAmount,
			Script: changeScript,
		}

		err = updater.AddOutputs([]psetv2.OutputArgs{connectorOutput, feeOutput})
		if err != nil {
			return nil, err
		}

		if changeOutput.Amount > 0 {
			err = updater.AddOutputs([]psetv2.OutputArgs{changeOutput})
			if err != nil {
				return nil, err
			}
		}

		base64, err := pset.ToBase64()
		if err != nil {
			return nil, err
		}

		connectorsPset[i] = base64

		if changeOutput.Amount > 0 {
			// update the previous input
			utx, err := pset.UnsignedTx()
			if err != nil {
				return nil, err
			}

			txID := utx.TxHash().String()

			previousInput = psetv2.InputArgs{
				Txid:    txID,
				TxIndex: 3, // the change output is always the third one
			}

			remainingAmount = changeOutput.Amount
			// continue only if there are a change
			continue
		}

		break
	}

	return connectorsPset, nil
}
