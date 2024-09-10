package covenantless

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/ark-network/ark/client/utils"
	"github.com/ark-network/ark/common/bitcointree"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/urfave/cli/v2"
)

func signPsbt(
	_ *cli.Context, ptx *psbt.Packet, explorer utils.Explorer, prvKey *secp256k1.PrivateKey,
) error {
	updater, err := psbt.NewUpdater(ptx)
	if err != nil {
		return err
	}

	for i, input := range updater.Upsbt.UnsignedTx.TxIn {
		if updater.Upsbt.Inputs[i].WitnessUtxo != nil {
			continue
		}

		prevoutTxHex, err := explorer.GetTxHex(input.PreviousOutPoint.Hash.String())
		if err != nil {
			return err
		}

		var prevoutTx wire.MsgTx

		if err := prevoutTx.Deserialize(hex.NewDecoder(strings.NewReader(prevoutTxHex))); err != nil {
			return err
		}

		utxo := prevoutTx.TxOut[input.PreviousOutPoint.Index]
		if utxo == nil {
			return fmt.Errorf("witness utxo not found")
		}

		if err := updater.AddInWitnessUtxo(utxo, i); err != nil {
			return err
		}

		if err := updater.AddInSighashType(txscript.SigHashDefault, i); err != nil {
			return err
		}
	}

	prevouts := make(map[wire.OutPoint]*wire.TxOut)

	for i, input := range updater.Upsbt.Inputs {
		outpoint := updater.Upsbt.UnsignedTx.TxIn[i].PreviousOutPoint
		prevouts[outpoint] = input.WitnessUtxo
	}

	prevoutFetcher := txscript.NewMultiPrevOutFetcher(
		prevouts,
	)

	txsighashes := txscript.NewTxSigHashes(updater.Upsbt.UnsignedTx, prevoutFetcher)

	for i, input := range ptx.Inputs {
		if len(input.TaprootLeafScript) > 0 {
			pubkey := prvKey.PubKey()
			for _, leaf := range input.TaprootLeafScript {
				closure, err := bitcointree.DecodeClosure(leaf.Script)
				if err != nil {
					return err
				}

				sign := false

				switch c := closure.(type) {
				case *bitcointree.CSVSigClosure:
					sign = bytes.Equal(c.Pubkey.SerializeCompressed()[1:], pubkey.SerializeCompressed()[1:])
				case *bitcointree.MultisigClosure:
					sign = bytes.Equal(c.Pubkey.SerializeCompressed()[1:], pubkey.SerializeCompressed()[1:])
				}

				if sign {
					if err := updater.AddInSighashType(txscript.SigHashDefault, i); err != nil {
						return err
					}

					hash := txscript.NewTapLeaf(leaf.LeafVersion, leaf.Script).TapHash()

					preimage, err := txscript.CalcTapscriptSignaturehash(
						txsighashes,
						txscript.SigHashDefault,
						ptx.UnsignedTx,
						i,
						prevoutFetcher,
						txscript.NewBaseTapLeaf(leaf.Script),
					)
					if err != nil {
						return err
					}

					sig, err := schnorr.Sign(
						prvKey,
						preimage,
					)
					if err != nil {
						return err
					}

					if !sig.Verify(preimage, prvKey.PubKey()) {
						return fmt.Errorf("signature verification failed")
					}

					if len(updater.Upsbt.Inputs[i].TaprootScriptSpendSig) == 0 {
						updater.Upsbt.Inputs[i].TaprootScriptSpendSig = make([]*psbt.TaprootScriptSpendSig, 0)
					}

					updater.Upsbt.Inputs[i].TaprootScriptSpendSig = append(updater.Upsbt.Inputs[i].TaprootScriptSpendSig, &psbt.TaprootScriptSpendSig{
						XOnlyPubKey: schnorr.SerializePubKey(prvKey.PubKey()),
						LeafHash:    hash.CloneBytes(),
						Signature:   sig.Serialize(),
						SigHash:     txscript.SigHashDefault,
					})
				}
			}
		}
	}

	return nil
}
