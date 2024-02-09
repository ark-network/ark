package txbuilder

import (
	"github.com/vulpemventures/go-elements/psetv2"
	"github.com/vulpemventures/go-elements/transaction"
)

func craftConnectorTx(
	input psetv2.InputArgs, outputs []psetv2.OutputArgs,
) (*psetv2.Pset, error) {
	ptx, _ := psetv2.New(nil, nil, nil)
	updater, _ := psetv2.NewUpdater(ptx)

	if err := updater.AddInputs(
		[]psetv2.InputArgs{input},
	); err != nil {
		return nil, err
	}

	// TODO: add prevout.

	if err := updater.AddOutputs(outputs); err != nil {
		return nil, err
	}

	return ptx, nil
}

func getConnectorInputs(pset *psetv2.Pset) ([]psetv2.InputArgs, []*transaction.TxOutput) {
	txID, _ := getPsetId(pset)

	inputs := make([]psetv2.InputArgs, 0, len(pset.Outputs))
	witnessUtxos := make([]*transaction.TxOutput, 0, len(pset.Outputs))

	for i, output := range pset.Outputs {
		utx, _ := pset.UnsignedTx()

		if output.Value == connectorAmount && len(output.Script) > 0 {
			inputs = append(inputs, psetv2.InputArgs{
				Txid:    txID,
				TxIndex: uint32(i),
			})
			witnessUtxos = append(witnessUtxos, utx.Outputs[i])
		}
	}

	return inputs, witnessUtxos
}
