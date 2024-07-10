// Copyright (C) 2015-2022 Lightning Labs and The Lightning Network Developers

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package btcwallet

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/wallet"
	log "github.com/sirupsen/logrus"
)

// signMethod defines the different ways a signer can sign, given a specific
// input.
type signMethod uint8

const (
	// witnessV0SignMethod denotes that a SegWit v0 (p2wkh, np2wkh, p2wsh)
	// input script should be signed.
	witnessV0SignMethod signMethod = 0

	// taprootKeySpendBIP0086SignMethod denotes that a SegWit v1 (p2tr)
	// input should be signed by using the BIP0086 method (commit to
	// internal key only).
	taprootKeySpendBIP0086SignMethod signMethod = 1

	// taprootKeySpendSignMethod denotes that a SegWit v1 (p2tr)
	// input should be signed by using a given taproot hash to commit to in
	// addition to the internal key.
	taprootKeySpendSignMethod signMethod = 2

	// taprootScriptSpendSignMethod denotes that a SegWit v1 (p2tr) input
	// should be spent using the script path and that a specific leaf script
	// should be signed for.
	taprootScriptSpendSignMethod signMethod = 3
)

func (s *service) signPsbt(packet *psbt.Packet) ([]uint32, error) {
	// In signedInputs we return the indices of psbt inputs that were signed
	// by our wallet. This way the caller can check if any inputs were signed.
	var signedInputs []uint32

	// Let's check that this is actually something we can and want to sign.
	// We need at least one input and one output. In addition each
	// input needs nonWitness Utxo or witness Utxo data specified.
	err := psbt.InputsReadyToSign(packet)
	if err != nil {
		return nil, err
	}

	// iterates over the inputs and set the default sighash flags
	updater, err := psbt.NewUpdater(packet)
	if err != nil {
		return nil, err
	}

	for idx, input := range packet.Inputs {
		if input.WitnessUtxo == nil {
			continue
		}

		script, err := txscript.ParsePkScript(input.WitnessUtxo.PkScript)
		if err != nil {
			return nil, fmt.Errorf("error detecting signing method, "+
				"couldn't parse pkScript: %v", err)
		}

		sighashType := txscript.SigHashAll

		if script.Class() == txscript.WitnessV1TaprootTy {
			sighashType = txscript.SigHashDefault
		}

		if err := updater.AddInSighashType(sighashType, idx); err != nil {
			return nil, err
		}
	}

	w, _ := s.loader.LoadedWallet()

	if err := w.Unlock(s.cfg.PrivatePassword, nil); err != nil {
		return nil, err
	}
	defer w.Lock()

	// Go through each input that doesn't have final witness data attached
	// to it already and try to sign it. If there is nothing more to sign or
	// there are inputs that we don't know how to sign, we won't return any
	// error. So it's possible we're not the final signer.
	tx := packet.UnsignedTx
	prevOutputFetcher := wallet.PsbtPrevOutputFetcher(packet)
	sigHashes := txscript.NewTxSigHashes(tx, prevOutputFetcher)
	for idx := range tx.TxIn {
		in := &packet.Inputs[idx]

		// We can only sign if we have UTXO information available. Since
		// we don't finalize, we just skip over any input that we know
		// we can't do anything with. Since we only support signing
		// witness inputs, we only look at the witness UTXO being set.
		if in.WitnessUtxo == nil {
			continue
		}

		// Skip this input if it's got final witness data attached.
		if len(in.FinalScriptWitness) > 0 {
			continue
		}

		managedAddr, _, _, err := w.ScriptForOutput(in.WitnessUtxo)
		if err != nil {
			log.Debugf("SignPsbt: Skipping input %d, error "+
				"fetching script for output: %v", idx, err)
			continue
		}

		privKey, err := managedAddr.PrivKey()
		if err != nil {
			log.Warnf("SignPsbt: Skipping input %d, error "+
				"deriving signing key: %v", idx, err)
			continue
		}

		// Do we need to tweak anything? Single or double tweaks are
		// sent as custom/proprietary fields in the PSBT input section.
		// privKey = maybeTweakPrivKeyPsbt(in.Unknowns, privKey)

		// What kind of signature is expected from us and do we have all
		// information we need?
		signMethod, err := validateSigningMethod(in)
		if err != nil {
			return nil, err
		}

		switch signMethod {
		// For p2wkh, np2wkh and p2wsh.
		case witnessV0SignMethod:
			err = signSegWitV0(in, tx, sigHashes, idx, privKey)

		// For p2tr BIP0086 key spend only.
		case taprootKeySpendBIP0086SignMethod:
			rootHash := make([]byte, 0)
			err = signSegWitV1KeySpend(
				in, tx, sigHashes, idx, privKey, rootHash,
			)

		// For p2tr with script commitment key spend path.
		case taprootKeySpendSignMethod:
			rootHash := in.TaprootMerkleRoot
			err = signSegWitV1KeySpend(
				in, tx, sigHashes, idx, privKey, rootHash,
			)

		// For p2tr script spend path.
		case taprootScriptSpendSignMethod:
			leafScript := in.TaprootLeafScript[0]
			leaf := txscript.TapLeaf{
				LeafVersion: leafScript.LeafVersion,
				Script:      leafScript.Script,
			}
			err = signSegWitV1ScriptSpend(
				in, tx, sigHashes, idx, privKey, leaf,
			)

		default:
			err = fmt.Errorf("unsupported signing method for "+
				"PSBT signing: %v", signMethod)
		}
		if err != nil {
			return nil, err
		}
		signedInputs = append(signedInputs, uint32(idx))
	}
	return signedInputs, nil
}

// validateSigningMethod attempts to detect the signing method that is required
// to sign for the given PSBT input and makes sure all information is available
// to do so.
func validateSigningMethod(in *psbt.PInput) (signMethod, error) {
	script, err := txscript.ParsePkScript(in.WitnessUtxo.PkScript)
	if err != nil {
		return 0, fmt.Errorf("error detecting signing method, "+
			"couldn't parse pkScript: %v", err)
	}

	switch script.Class() {
	case txscript.WitnessV0PubKeyHashTy, txscript.ScriptHashTy,
		txscript.WitnessV0ScriptHashTy:

		return witnessV0SignMethod, nil

	case txscript.WitnessV1TaprootTy:
		if len(in.TaprootBip32Derivation) == 0 {
			return 0, fmt.Errorf("cannot sign for taproot input " +
				"without taproot BIP0032 derivation info")
		}

		// Currently, we only support creating one signature per input.
		//
		// TODO(guggero): Should we support signing multiple paths at
		// the same time? What are the performance and security
		// implications?
		if len(in.TaprootBip32Derivation) > 1 {
			return 0, fmt.Errorf("unsupported multiple taproot " +
				"BIP0032 derivation info found, can only " +
				"sign for one at a time")
		}

		derivation := in.TaprootBip32Derivation[0]
		switch {
		// No leaf hashes means this is the internal key we're signing
		// with, so it's a key spend. And no merkle root means this is
		// a BIP0086 output we're signing for.
		case len(derivation.LeafHashes) == 0 &&
			len(in.TaprootMerkleRoot) == 0:

			return taprootKeySpendBIP0086SignMethod, nil

		// A non-empty merkle root means we committed to a taproot hash
		// that we need to use in the tap tweak.
		case len(derivation.LeafHashes) == 0:
			// Getting here means the merkle root isn't empty, but
			// is it exactly the length we need?
			if len(in.TaprootMerkleRoot) != sha256.Size {
				return 0, fmt.Errorf("invalid taproot merkle "+
					"root length, got %d expected %d",
					len(in.TaprootMerkleRoot), sha256.Size)
			}

			return taprootKeySpendSignMethod, nil

		// Currently, we only support signing for one leaf at a time.
		//
		// TODO(guggero): Should we support signing multiple paths at
		// the same time? What are the performance and security
		// implications?
		case len(derivation.LeafHashes) == 1:
			// If we're supposed to be signing for a leaf hash, we
			// also expect the leaf script that hashes to that hash
			// in the appropriate field.
			if len(in.TaprootLeafScript) != 1 {
				return 0, fmt.Errorf("specified leaf hash in " +
					"taproot BIP0032 derivation but " +
					"missing taproot leaf script")
			}

			leafScript := in.TaprootLeafScript[0]
			leaf := txscript.TapLeaf{
				LeafVersion: leafScript.LeafVersion,
				Script:      leafScript.Script,
			}
			leafHash := leaf.TapHash()
			if !bytes.Equal(leafHash[:], derivation.LeafHashes[0]) {
				return 0, fmt.Errorf("specified leaf hash in" +
					"taproot BIP0032 derivation but " +
					"corresponding taproot leaf script " +
					"was not found")
			}

			return taprootScriptSpendSignMethod, nil

		default:
			return 0, fmt.Errorf("unsupported number of leaf " +
				"hashes in taproot BIP0032 derivation info, " +
				"can only sign for one at a time")
		}

	default:
		return 0, fmt.Errorf("unsupported script class for signing "+
			"PSBT: %v", script.Class())
	}
}

// SignSegWitV0 attempts to generate a signature for a SegWit version 0 input
// and stores it in the PartialSigs (and FinalScriptSig for np2wkh addresses)
// field.
func signSegWitV0(in *psbt.PInput, tx *wire.MsgTx,
	sigHashes *txscript.TxSigHashes, idx int,
	privKey *btcec.PrivateKey) error {

	pubKeyBytes := privKey.PubKey().SerializeCompressed()

	// Extract the correct witness and/or legacy scripts now, depending on
	// the type of input we sign. The txscript package has the peculiar
	// requirement that the PkScript of a P2PKH must be given as the witness
	// script in order for it to arrive at the correct sighash. That's why
	// we call it subScript here instead of witness script.
	subScript := prepareScriptsV0(in)

	// We have everything we need for signing the input now.
	sig, err := txscript.RawTxInWitnessSignature(
		tx, sigHashes, idx, in.WitnessUtxo.Value, subScript,
		in.SighashType, privKey,
	)
	if err != nil {
		return fmt.Errorf("error signing input %d: %w", idx, err)
	}
	in.PartialSigs = append(in.PartialSigs, &psbt.PartialSig{
		PubKey:    pubKeyBytes,
		Signature: sig,
	})

	return nil
}

// prepareScriptsV0 returns the appropriate witness v0 and/or legacy scripts,
// depending on the type of input that should be signed.
func prepareScriptsV0(in *psbt.PInput) []byte {
	switch {
	// It's a NP2WKH input:
	case len(in.RedeemScript) > 0:
		return in.RedeemScript

	// It's a P2WSH input:
	case len(in.WitnessScript) > 0:
		return in.WitnessScript

	// It's a P2WKH input:
	default:
		return in.WitnessUtxo.PkScript
	}
}

// signSegWitV1KeySpend attempts to generate a signature for a SegWit version 1
// (p2tr) input and stores it in the TaprootKeySpendSig field.
func signSegWitV1KeySpend(in *psbt.PInput, tx *wire.MsgTx,
	sigHashes *txscript.TxSigHashes, idx int, privKey *btcec.PrivateKey,
	tapscriptRootHash []byte) error {

	rawSig, err := txscript.RawTxInTaprootSignature(
		tx, sigHashes, idx, in.WitnessUtxo.Value,
		in.WitnessUtxo.PkScript, tapscriptRootHash, in.SighashType,
		privKey,
	)
	if err != nil {
		return fmt.Errorf("error signing taproot input %d: %w", idx,
			err)
	}

	in.TaprootKeySpendSig = rawSig

	return nil
}

// signSegWitV1ScriptSpend attempts to generate a signature for a SegWit version
// 1 (p2tr) input and stores it in the TaprootScriptSpendSig field.
func signSegWitV1ScriptSpend(in *psbt.PInput, tx *wire.MsgTx,
	sigHashes *txscript.TxSigHashes, idx int, privKey *btcec.PrivateKey,
	leaf txscript.TapLeaf) error {

	rawSig, err := txscript.RawTxInTapscriptSignature(
		tx, sigHashes, idx, in.WitnessUtxo.Value,
		in.WitnessUtxo.PkScript, leaf, in.SighashType, privKey,
	)
	if err != nil {
		return fmt.Errorf("error signing taproot script input %d: %w",
			idx, err)
	}

	leafHash := leaf.TapHash()
	in.TaprootScriptSpendSig = append(
		in.TaprootScriptSpendSig, &psbt.TaprootScriptSpendSig{
			XOnlyPubKey: in.TaprootBip32Derivation[0].XOnlyPubKey,
			LeafHash:    leafHash[:],
			// We snip off the sighash flag from the end (if it was
			// specified in the first place.)
			Signature: rawSig[:schnorr.SignatureSize],
			SigHash:   in.SighashType,
		},
	)

	return nil
}
