package singlekeywallet

import (
	"bytes"
	"context"
	"fmt"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/pkg/client-sdk/explorer"
	"github.com/ark-network/ark/pkg/client-sdk/internal/utils"
	"github.com/ark-network/ark/pkg/client-sdk/store"
	"github.com/ark-network/ark/pkg/client-sdk/wallet"
	walletstore "github.com/ark-network/ark/pkg/client-sdk/wallet/singlekey/store"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/vulpemventures/go-elements/payment"
	"github.com/vulpemventures/go-elements/psetv2"
	"github.com/vulpemventures/go-elements/transaction"
)

type liquidWallet struct {
	*singlekeyWallet
}

func NewLiquidWallet(
	configStore store.ConfigStore, walletStore walletstore.WalletStore,
) (wallet.WalletService, error) {
	walletData, err := walletStore.GetWallet()
	if err != nil {
		return nil, err
	}
	return &liquidWallet{
		&singlekeyWallet{configStore, walletStore, nil, walletData},
	}, nil
}

func (w *liquidWallet) GetAddresses(
	ctx context.Context,
) ([]string, []string, []string, error) {
	offchainAddr, onchainAddr, redemptionAddr, err := w.getAddress(ctx)
	if err != nil {
		return nil, nil, nil, err
	}

	offchainAddrs := []string{offchainAddr}
	onchainAddrs := []string{onchainAddr}
	redemptionAddrs := []string{redemptionAddr}
	return offchainAddrs, onchainAddrs, redemptionAddrs, nil
}

func (w *liquidWallet) NewAddress(
	ctx context.Context, _ bool,
) (string, string, error) {
	offchainAddr, onchainAddr, _, err := w.getAddress(ctx)
	if err != nil {
		return "", "", err
	}
	return offchainAddr, onchainAddr, nil
}

func (w *liquidWallet) NewAddresses(
	ctx context.Context, _ bool, num int,
) ([]string, []string, error) {
	offchainAddr, onchainAddr, _, err := w.getAddress(ctx)
	if err != nil {
		return nil, nil, err
	}

	offchainAddrs := make([]string, 0, num)
	onchainAddrs := make([]string, 0, num)
	for i := 0; i < num; i++ {
		offchainAddrs = append(offchainAddrs, offchainAddr)
		onchainAddrs = append(onchainAddrs, onchainAddr)
	}
	return offchainAddrs, onchainAddrs, nil
}

func (s *liquidWallet) SignTransaction(
	ctx context.Context, explorerSvc explorer.Explorer, tx string,
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

	storeData, err := s.configStore.GetData(ctx)
	if err != nil {
		return "", err
	}
	liquidNet := utils.ToElementsNetwork(storeData.Network)
	p2wpkh := payment.FromPublicKey(s.walletData.Pubkey, &liquidNet, nil)
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

	serializedPubKey := s.walletData.Pubkey.SerializeCompressed()

	for i, input := range pset.Inputs {
		prevout := input.GetUtxo()

		if bytes.Equal(prevout.Script, onchainWalletScript) {
			p, err := payment.FromScript(prevout.Script, &liquidNet, nil)
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
				i, signatureWithSighashType, serializedPubKey, nil, nil,
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
					sign = bytes.Equal(c.Pubkey.SerializeCompressed()[1:], serializedPubKey[1:])
				case *tree.ForfeitClosure:
					sign = bytes.Equal(c.Pubkey.SerializeCompressed()[1:], serializedPubKey[1:])
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

					sig, err := schnorr.Sign(s.privateKey, preimage[:])
					if err != nil {
						return "", err
					}

					tapScriptSig := psetv2.TapScriptSig{
						PartialSig: psetv2.PartialSig{
							PubKey:    schnorr.SerializePubKey(s.walletData.Pubkey),
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

func (w *liquidWallet) getAddress(
	ctx context.Context,
) (string, string, string, error) {
	if w.walletData == nil {
		return "", "", "", fmt.Errorf("wallet not initialized")
	}

	data, err := w.configStore.GetData(ctx)
	if err != nil {
		return "", "", "", err
	}

	offchainAddr, err := common.EncodeAddress(
		data.Network.Addr, w.walletData.Pubkey, data.AspPubkey,
	)
	if err != nil {
		return "", "", "", err
	}

	liquidNet := utils.ToElementsNetwork(data.Network)

	p2wpkh := payment.FromPublicKey(w.walletData.Pubkey, &liquidNet, nil)
	onchainAddr, err := p2wpkh.WitnessPubKeyHash()
	if err != nil {
		return "", "", "", err
	}

	_, _, _, redemptionAddr, err := tree.ComputeVtxoTaprootScript(
		w.walletData.Pubkey, data.AspPubkey, uint(data.UnilateralExitDelay), liquidNet,
	)
	if err != nil {
		return "", "", "", err
	}

	return offchainAddr, onchainAddr, redemptionAddr, nil
}
