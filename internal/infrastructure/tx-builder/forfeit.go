package txbuilder

import (
	"github.com/vulpemventures/go-elements/network"
	"github.com/vulpemventures/go-elements/psetv2"
)

func createForfeitTx(
	connectorInput psetv2.InputArgs,
	vtxoInput psetv2.InputArgs,
	vtxoAmount uint64,
	aspScript []byte,
	net *network.Network,
) (forfeitTx string, err error) {
	pset, err := psetv2.New(nil, nil, nil)
	if err != nil {
		return "", err
	}

	updater, err := psetv2.NewUpdater(pset)
	if err != nil {
		return "", err
	}

	err = updater.AddInputs([]psetv2.InputArgs{connectorInput, vtxoInput})
	if err != nil {
		return "", err
	}

	err = updater.AddOutputs([]psetv2.OutputArgs{
		{
			Asset:  net.AssetID,
			Amount: vtxoAmount,
			Script: aspScript,
		},
	})
	if err != nil {
		return "", err
	}

	return pset.ToBase64()
}
