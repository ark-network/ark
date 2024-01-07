package main

import (
	"bytes"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/vulpemventures/go-elements/address"
	"github.com/vulpemventures/go-elements/payment"
	"github.com/vulpemventures/go-elements/psetv2"
	"github.com/vulpemventures/go-elements/taproot"
	"github.com/vulpemventures/go-elements/transaction"
)

func checksigScript(pubkey *secp256k1.PublicKey) ([]byte, error) {
	key := schnorr.SerializePubKey(pubkey)
	return txscript.NewScriptBuilder().AddData(key).AddOp(txscript.OP_CHECKSIG).Script()
}

func checksigTapLeafScript(pubkey *secp256k1.PublicKey) (*taproot.TapElementsLeaf, error) {
	script, err := checksigScript(pubkey)
	if err != nil {
		return nil, err
	}

	tapLeaf := taproot.NewBaseTapElementsLeaf(script)
	return &tapLeaf, nil
}

func signPset(
	pset *psetv2.Pset,
	explorer Explorer,
	prvKey *secp256k1.PrivateKey,
) error {
	updater, err := psetv2.NewUpdater(pset)
	if err != nil {
		return err
	}

	for i, input := range pset.Inputs {
		if input.WitnessUtxo != nil {
			continue
		}

		prevoutTxHex, err := explorer.GetTxHex(chainhash.Hash(input.PreviousTxid).String())
		if err != nil {
			return err
		}

		prevoutTx, err := transaction.NewTxFromHex(prevoutTxHex)
		if err != nil {
			return err
		}

		utxo := prevoutTx.Outputs[input.PreviousTxIndex]
		if utxo == nil {
			return fmt.Errorf("witness utxo not found")
		}

		if err := updater.AddInWitnessUtxo(i, utxo); err != nil {
			return err
		}

		sighashType := txscript.SigHashAll

		if utxo.Script[0] == txscript.OP_1 {
			sighashType = txscript.SigHashDefault
		}

		if err := updater.AddInSighashType(i, sighashType); err != nil {
			return err
		}
	}

	signer, err := psetv2.NewSigner(updater.Pset)
	if err != nil {
		return err
	}

	_, onchainAddr, err := getAddress()
	if err != nil {
		return err
	}

	onchainWalletScript, err := address.ToOutputScript(onchainAddr)
	if err != nil {
		return err
	}

	utx, err := pset.UnsignedTx()
	if err != nil {
		return err
	}

	_, liquidNet, err := getNetwork()
	if err != nil {
		return err
	}

	prevoutsScripts := make([][]byte, 0)
	prevoutsValues := make([][]byte, 0)
	prevoutsAssets := make([][]byte, 0)

	for _, input := range pset.Inputs {
		prevoutsScripts = append(prevoutsScripts, input.WitnessUtxo.Script)
		prevoutsValues = append(prevoutsValues, input.WitnessUtxo.Value)
		prevoutsAssets = append(prevoutsAssets, input.WitnessUtxo.Asset)
	}

	for i, input := range pset.Inputs {
		if bytes.Equal(input.WitnessUtxo.Script, onchainWalletScript) {
			p, err := payment.FromScript(input.WitnessUtxo.Script, liquidNet, nil)
			if err != nil {
				return err
			}

			preimage := utx.HashForWitnessV0(
				i,
				p.Script,
				input.WitnessUtxo.Value,
				txscript.SigHashAll,
			)

			sig := ecdsa.Sign(
				prvKey,
				preimage[:],
			)

			signatureWithSighashType := append(sig.Serialize(), byte(txscript.SigHashAll))

			err = signer.SignInput(i, signatureWithSighashType, prvKey.PubKey().SerializeCompressed(), nil, nil)
			if err != nil {
				fmt.Println("error signing input: ", err)
				return err
			}
			continue
		}

		pubkey, err := getWalletPublicKey()
		if err != nil {
			return err
		}

		leafScript, err := checksigScript(pubkey)
		if err != nil {
			return err
		}

		if len(input.TapLeafScript) > 0 {
			genesis, err := chainhash.NewHashFromStr(liquidNet.GenesisBlockHash)
			if err != nil {
				return err
			}
			for _, leaf := range input.TapLeafScript {
				if bytes.Equal(leaf.Script, leafScript) {
					fmt.Println("found tap leaf script")

					hash := leaf.TapHash()

					preimage := utx.HashForWitnessV1(
						i,
						prevoutsScripts,
						prevoutsAssets,
						prevoutsValues,
						txscript.SigHashDefault,
						genesis,
						&hash,
						nil,
					)

					sig, err := schnorr.Sign(
						prvKey,
						preimage[:],
					)
					if err != nil {
						return err
					}

					tapScriptSig := psetv2.TapScriptSig{
						PartialSig: psetv2.PartialSig{
							PubKey:    schnorr.SerializePubKey(prvKey.PubKey()),
							Signature: sig.Serialize(),
						},
						LeafHash: hash.CloneBytes(),
					}

					if err := signer.SignTaprootInputTapscriptSig(i, tapScriptSig); err != nil {
						return err
					}

					continue
				}
			}
		}

	}

	for i, input := range pset.Inputs {
		if len(input.PartialSigs) > 0 {
			valid, err := pset.ValidateInputSignatures(i)
			if err != nil {
				return err
			}

			if !valid {
				return fmt.Errorf("invalid signature for input %d", i)
			}
		}
	}

	return nil
}
