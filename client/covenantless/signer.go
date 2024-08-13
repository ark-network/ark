package covenantless

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/ark-network/ark/client/utils"
	"github.com/ark-network/ark/common/bitcointree"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/urfave/cli/v2"
)

func signPsbt(
	ctx *cli.Context, ptx *psbt.Packet, explorer utils.Explorer, prvKey *secp256k1.PrivateKey,
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

		sighashType := txscript.SigHashAll

		if utxo.PkScript[0] == txscript.OP_1 {
			sighashType = txscript.SigHashDefault
		}

		if err := updater.AddInSighashType(sighashType, i); err != nil {
			return err
		}
	}

	_, onchainAddr, _, err := getAddress(ctx)
	if err != nil {
		return err
	}

	onchainWalletScript, err := txscript.PayToAddrScript(onchainAddr)
	if err != nil {
		return err
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
		if bytes.Equal(input.WitnessUtxo.PkScript, onchainWalletScript) {
			if err := updater.AddInSighashType(txscript.SigHashAll, i); err != nil {
				return err
			}

			preimage, err := txscript.CalcWitnessSigHash(
				input.WitnessUtxo.PkScript,
				txsighashes,
				txscript.SigHashAll,
				updater.Upsbt.UnsignedTx,
				i,
				int64(input.WitnessUtxo.Value),
			)
			if err != nil {
				return err
			}

			sig := ecdsa.Sign(
				prvKey,
				preimage,
			)

			signatureWithSighashType := append(sig.Serialize(), byte(txscript.SigHashAll))

			updater.Upsbt.Inputs[i].PartialSigs = []*psbt.PartialSig{
				{
					PubKey:    prvKey.PubKey().SerializeCompressed(),
					Signature: signatureWithSighashType,
				},
			}

			continue
		}

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

					updater.Upsbt.Inputs[i].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{
						{
							XOnlyPubKey: schnorr.SerializePubKey(prvKey.PubKey()),
							LeafHash:    hash.CloneBytes(),
							Signature:   sig.Serialize(),
							SigHash:     txscript.SigHashDefault,
						},
					}
				}
			}
		}

	}

	return nil
}
