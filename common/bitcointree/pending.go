package bitcointree

import (
	"fmt"

	"github.com/ark-network/ark/common"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func BuildRedeemTx(
	vtxos []common.VtxoInput,
	outputs []*wire.TxOut,
) (string, error) {
	if len(vtxos) <= 0 {
		return "", fmt.Errorf("missing vtxos")
	}

	ins := make([]*wire.OutPoint, 0, len(vtxos))
	witnessUtxos := make(map[int]*wire.TxOut)
	tapscripts := make(map[int]*psbt.TaprootTapLeafScript)

	for index, vtxo := range vtxos {
		rootHash := vtxo.Tapscript.ControlBlock.RootHash(vtxo.Tapscript.RevealedScript)
		taprootKey := txscript.ComputeTaprootOutputKey(UnspendableKey(), rootHash)

		vtxoOutputScript, err := common.P2TRScript(taprootKey)
		if err != nil {
			return "", err
		}

		witnessUtxos[index] = &wire.TxOut{
			Value:    vtxo.Amount,
			PkScript: vtxoOutputScript,
		}

		ctrlBlockBytes, err := vtxo.Tapscript.ControlBlock.ToBytes()
		if err != nil {
			return "", err
		}

		tapscripts[index] = &psbt.TaprootTapLeafScript{
			ControlBlock: ctrlBlockBytes,
			Script:       vtxo.Tapscript.RevealedScript,
			LeafVersion:  txscript.BaseLeafVersion,
		}

		ins = append(ins, vtxo.Outpoint)
	}

	sequences := make([]uint32, len(ins))
	for i := range sequences {
		sequences[i] = wire.MaxTxInSequenceNum
	}

	redeemPtx, err := psbt.New(
		ins, outputs, 2, 0, sequences,
	)
	if err != nil {
		return "", err
	}

	for i := range redeemPtx.Inputs {
		redeemPtx.Inputs[i].WitnessUtxo = witnessUtxos[i]
		redeemPtx.Inputs[i].TaprootLeafScript = []*psbt.TaprootTapLeafScript{tapscripts[i]}
	}

	redeemTx, err := redeemPtx.B64Encode()
	if err != nil {
		return "", err
	}

	return redeemTx, nil
}
