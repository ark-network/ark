package arksdk

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"

	"github.com/ark-network/ark/common/tree"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/vulpemventures/go-elements/payment"
	"github.com/vulpemventures/go-elements/psetv2"
	"github.com/vulpemventures/go-elements/transaction"
)

type Wallet interface {
	PubKey() *secp256k1.PublicKey
	PubKeySerializeCompressed() []byte
	SignTransaction(explorerSvc Explorer, pset string) (string, error)
}

type singleKeyWallet struct {
	privateKey  *secp256k1.PrivateKey
	pubkey      *secp256k1.PublicKey
	walletStore WalletStore
}

func NewSingleKeyWallet(
	ctx context.Context,
	walletStore WalletStore,
) (Wallet, error) {
	var privateKey *secp256k1.PrivateKey

	privKeyHex, err := walletStore.GetPrivateKeyHex()
	if err != nil {
		return nil, err
	}

	pkNew := false
	if len(privKeyHex) <= 0 {
		pk, err := walletStore.CreatePrivateKey()
		if err != nil {
			return nil, err
		}

		privateKey = pk
		pkNew = true
	} else {
		privKeyBytes, err := hex.DecodeString(privKeyHex)
		if err != nil {
			return nil, err
		}

		privateKey = secp256k1.PrivKeyFromBytes(privKeyBytes)
	}

	if pkNew {
		if err := walletStore.Save(ctx); err != nil {
			return nil, err
		}
	}

	return &singleKeyWallet{
		privateKey: privateKey,
		pubkey:     privateKey.PubKey(),
	}, nil
}

func (s *singleKeyWallet) PrivKey() *secp256k1.PrivateKey {
	return s.privateKey
}

func (s *singleKeyWallet) PubKey() *secp256k1.PublicKey {
	return s.pubkey
}

func (s *singleKeyWallet) PubKeySerializeCompressed() []byte {
	return s.pubkey.SerializeCompressed()
}

func (s *singleKeyWallet) SignTransaction(
	explorerSvc Explorer, tx string,
) (string, error) {
	pset, err := psetv2.NewPsetFromBase64(tx)
	if err != nil {
		return "", fmt.Errorf("invalid pset: %s", err)
	}
	updater, err := psetv2.NewUpdater(pset)
	if err != nil {
		return "", err
	}

	for i, input := range pset.Inputs {
		if input.WitnessUtxo != nil {
			continue
		}

		prevoutTxHex, err := explorerSvc.GetTxHex(chainhash.Hash(input.PreviousTxid).String())
		if err != nil {
			return "", err
		}

		prevoutTx, err := transaction.NewTxFromHex(prevoutTxHex)
		if err != nil {
			return "", err
		}

		utxo := prevoutTx.Outputs[input.PreviousTxIndex]
		if utxo == nil {
			return "", fmt.Errorf("witness utxo not found")
		}

		if err := updater.AddInWitnessUtxo(i, utxo); err != nil {
			return "", err
		}

		sighashType := txscript.SigHashAll

		if utxo.Script[0] == txscript.OP_1 {
			sighashType = txscript.SigHashDefault
		}

		if err := updater.AddInSighashType(i, sighashType); err != nil {
			return "", err
		}
	}

	signer, err := psetv2.NewSigner(updater.Pset)
	if err != nil {
		return "", err
	}

	liquidNet := explorerSvc.GetNetwork()
	p2wpkh := payment.FromPublicKey(s.pubkey, liquidNet, nil)
	onchainWalletScript := p2wpkh.WitnessScript

	utx, err := pset.UnsignedTx()
	if err != nil {
		return "", err
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
		prevout := input.GetUtxo()

		if bytes.Equal(prevout.Script, onchainWalletScript) {
			p, err := payment.FromScript(prevout.Script, liquidNet, nil)
			if err != nil {
				return "", err
			}

			preimage := utx.HashForWitnessV0(
				i, p.Script, prevout.Value, txscript.SigHashAll,
			)

			sig := ecdsa.Sign(s.privateKey, preimage[:])

			signatureWithSighashType := append(
				sig.Serialize(), byte(txscript.SigHashAll),
			)

			err = signer.SignInput(
				i, signatureWithSighashType, s.PubKeySerializeCompressed(), nil, nil,
			)
			if err != nil {
				return "", err
			}
			continue
		}

		if len(input.TapLeafScript) > 0 {
			genesis, err := chainhash.NewHashFromStr(liquidNet.GenesisBlockHash)
			if err != nil {
				return "", err
			}

			for _, leaf := range input.TapLeafScript {
				closure, err := tree.DecodeClosure(leaf.Script)
				if err != nil {
					return "", err
				}

				sign := false
				switch c := closure.(type) {
				case *tree.CSVSigClosure:
					sign = bytes.Equal(c.Pubkey.SerializeCompressed()[1:], s.pubkey.SerializeCompressed()[1:])
				case *tree.ForfeitClosure:
					sign = bytes.Equal(c.Pubkey.SerializeCompressed()[1:], s.pubkey.SerializeCompressed()[1:])
				}

				if sign {
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

					sig, err := schnorr.Sign(s.PrivKey(), preimage[:])
					if err != nil {
						return "", err
					}

					tapScriptSig := psetv2.TapScriptSig{
						PartialSig: psetv2.PartialSig{
							PubKey:    schnorr.SerializePubKey(s.PubKey()),
							Signature: sig.Serialize(),
						},
						LeafHash: hash.CloneBytes(),
					}

					if err := signer.SignTaprootInputTapscriptSig(i, tapScriptSig); err != nil {
						return "", err
					}
				}
			}
		}

	}

	for i, input := range pset.Inputs {
		if len(input.PartialSigs) > 0 {
			valid, err := pset.ValidateInputSignatures(i)
			if err != nil {
				return "", err
			}

			if !valid {
				return "", fmt.Errorf("invalid signature for input %d", i)
			}
		}
	}

	return pset.ToBase64()
}
