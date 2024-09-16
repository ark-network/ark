package txbuilder

import (
	"github.com/vulpemventures/go-elements/elementsutil"
	"github.com/vulpemventures/go-elements/psetv2"
	"github.com/vulpemventures/go-elements/transaction"
)

func craftConnectorTx(
	input psetv2.InputArgs, inputScript []byte, outputs []psetv2.OutputArgs, feeAmount uint64,
) (*psetv2.Pset, error) {
	ptx, _ := psetv2.New(nil, nil, nil)
	updater, _ := psetv2.NewUpdater(ptx)

	if err := updater.AddInputs(
		[]psetv2.InputArgs{input},
	); err != nil {
		return nil, err
	}

	var asset []byte
	amount := feeAmount
	for _, output := range outputs {
		amount += output.Amount
		if asset == nil {
			var err error
			asset, err = elementsutil.AssetHashToBytes(output.Asset)
			if err != nil {
				return nil, err
			}
		}
	}

	value, err := elementsutil.ValueToBytes(amount)
	if err != nil {
		return nil, err
	}

	if err := updater.AddInWitnessUtxo(0, transaction.NewTxOutput(asset, value, inputScript)); err != nil {
		return nil, err
	}

	feeOutput := psetv2.OutputArgs{
		Asset:  outputs[0].Asset,
		Amount: feeAmount,
	}

	if err := updater.AddOutputs(append(outputs, feeOutput)); err != nil {
		return nil, err
	}

	return ptx, nil
}

func getConnectorInputs(pset *psetv2.Pset, connectorAmount uint64) ([]psetv2.InputArgs, []*transaction.TxOutput) {
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
