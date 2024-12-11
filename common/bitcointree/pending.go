package bitcointree

import (
	"fmt"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/tree"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

const (
	// signal CLTV with input sequence number
	cltvSequence = wire.MaxTxInSequenceNum - 1
)

func BuildRedeemTx(
	vtxos []common.VtxoInput,
	outputs []*wire.TxOut,
) (string, error) {
	if len(vtxos) <= 0 {
		return "", fmt.Errorf("missing vtxos")
	}

	ins := make([]*wire.OutPoint, 0, len(vtxos))
	sequences := make([]uint32, 0, len(vtxos))
	witnessUtxos := make(map[int]*wire.TxOut)
	tapscripts := make(map[int]*psbt.TaprootTapLeafScript)

	txLocktime := common.AbsoluteLocktime(0)

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

		closure, err := tree.DecodeClosure(vtxo.Tapscript.RevealedScript)
		if err != nil {
			return "", err
		}

		// check if the closure is a CLTV multisig closure,
		// if so, update the tx locktime
		var locktime *common.AbsoluteLocktime
		if cltv, ok := closure.(*tree.CLTVMultisigClosure); ok {
			locktime = &cltv.Locktime
			if locktime.IsSeconds() {
				if txLocktime != 0 && !txLocktime.IsSeconds() {
					return "", fmt.Errorf("mixed absolute locktime types")
				}
			} else {
				if txLocktime != 0 && txLocktime.IsSeconds() {
					return "", fmt.Errorf("mixed absolute locktime types")
				}
			}

			if *locktime > txLocktime {
				txLocktime = *locktime
			}
		}

		ins = append(ins, vtxo.Outpoint)
		if locktime != nil {
			sequences = append(sequences, cltvSequence)
		} else {
			sequences = append(sequences, wire.MaxTxInSequenceNum)
		}
	}

	redeemPtx, err := psbt.New(
		ins, outputs, 2, uint32(txLocktime), sequences,
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
