package singlekeywallet

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/bitcointree"
	"github.com/ark-network/ark/pkg/client-sdk/explorer"
	"github.com/ark-network/ark/pkg/client-sdk/internal/utils"
	"github.com/ark-network/ark/pkg/client-sdk/store"
	"github.com/ark-network/ark/pkg/client-sdk/wallet"
	walletstore "github.com/ark-network/ark/pkg/client-sdk/wallet/singlekey/store"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

type bitcoinWallet struct {
	*singlekeyWallet
}

func NewBitcoinWallet(
	configStore store.ConfigStore, walletStore walletstore.WalletStore,
) (wallet.WalletService, error) {
	walletData, err := walletStore.GetWallet()
	if err != nil {
		return nil, err
	}
	return &bitcoinWallet{
		&singlekeyWallet{configStore, walletStore, nil, walletData},
	}, nil
}

func (w *bitcoinWallet) GetAddresses(
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

func (w *bitcoinWallet) NewAddress(
	ctx context.Context, _ bool,
) (string, string, error) {
	offchainAddr, onchainAddr, _, err := w.getAddress(ctx)
	if err != nil {
		return "", "", err
	}
	return offchainAddr, onchainAddr, nil
}

func (w *bitcoinWallet) NewAddresses(
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

func (s *bitcoinWallet) SignTransaction(
	ctx context.Context, explorerSvc explorer.Explorer, tx string,
) (string, error) {
	ptx, err := psbt.NewFromRawBytes(strings.NewReader(tx), true)
	if err != nil {
		return "", err
	}

	updater, err := psbt.NewUpdater(ptx)
	if err != nil {
		return "", err
	}

	data, err := s.configStore.GetData(ctx)
	if err != nil {
		return "", err
	}

	for i, input := range updater.Upsbt.UnsignedTx.TxIn {
		if updater.Upsbt.Inputs[i].WitnessUtxo != nil {
			continue
		}

		prevoutTxHex, err := explorerSvc.GetTxHex(input.PreviousOutPoint.Hash.String())
		if err != nil {
			return "", err
		}

		var prevoutTx wire.MsgTx

		if err := prevoutTx.Deserialize(hex.NewDecoder(strings.NewReader(prevoutTxHex))); err != nil {
			return "", err
		}

		utxo := prevoutTx.TxOut[input.PreviousOutPoint.Index]
		if utxo == nil {
			return "", fmt.Errorf("witness utxo not found")
		}

		if err := updater.AddInWitnessUtxo(utxo, i); err != nil {
			return "", err
		}

		sighashType := txscript.SigHashAll

		if utxo.PkScript[0] == txscript.OP_1 {
			sighashType = txscript.SigHashDefault
		}

		if err := updater.AddInSighashType(sighashType, i); err != nil {
			return "", err
		}
	}

	_, onchainAddr, _, err := s.getAddress(ctx)
	if err != nil {
		return "", err
	}
	net := utils.ToBitcoinNetwork(data.Network)
	addr, _ := btcutil.DecodeAddress(onchainAddr, &net)
	onchainWalletScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return "", err
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
				return "", err
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
				return "", err
			}

			sig := ecdsa.Sign(s.privateKey, preimage)
			signatureWithSighashType := append(sig.Serialize(), byte(txscript.SigHashAll))

			updater.Upsbt.Inputs[i].PartialSigs = []*psbt.PartialSig{
				{
					PubKey:    s.walletData.Pubkey.SerializeCompressed(),
					Signature: signatureWithSighashType,
				},
			}

			continue
		}

		if len(input.TaprootLeafScript) > 0 {
			pubkey := s.walletData.Pubkey
			for _, leaf := range input.TaprootLeafScript {
				closure, err := bitcointree.DecodeClosure(leaf.Script)
				if err != nil {
					return "", err
				}

				sign := false

				switch c := closure.(type) {
				case *bitcointree.CSVSigClosure:
					sign = bytes.Equal(c.Pubkey.SerializeCompressed()[1:], pubkey.SerializeCompressed()[1:])
				case *bitcointree.ForfeitClosure:
					sign = bytes.Equal(c.Pubkey.SerializeCompressed()[1:], pubkey.SerializeCompressed()[1:])
				}

				if sign {
					if err := updater.AddInSighashType(txscript.SigHashDefault, i); err != nil {
						return "", err
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
						return "", err
					}

					sig, err := schnorr.Sign(s.privateKey, preimage)
					if err != nil {
						return "", err
					}

					if !sig.Verify(preimage, pubkey) {
						return "", fmt.Errorf("signature verification failed")
					}

					updater.Upsbt.Inputs[i].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{
						{
							XOnlyPubKey: schnorr.SerializePubKey(pubkey),
							LeafHash:    hash.CloneBytes(),
							Signature:   sig.Serialize(),
							SigHash:     txscript.SigHashDefault,
						},
					}
				}
			}
		}

	}

	return ptx.B64Encode()
}

func (w *bitcoinWallet) getAddress(
	ctx context.Context,
) (string, string, string, error) {
	if w.walletData == nil {
		return "", "", "", fmt.Errorf("wallet not initialized")
	}

	data, err := w.configStore.GetData(ctx)
	if err != nil {
		return "", "", "", err
	}

	offchainAddr, err := common.EncodeAddress(data.Network.Addr, w.walletData.Pubkey, data.AspPubkey)
	if err != nil {
		return "", "", "", err
	}

	netParams := utils.ToBitcoinNetwork(data.Network)

	onchainAddr, err := btcutil.NewAddressWitnessPubKeyHash(btcutil.Hash160(w.walletData.Pubkey.SerializeCompressed()), &netParams)
	if err != nil {
		return "", "", "", err
	}

	vtxoTapKey, _, err := bitcointree.ComputeVtxoTaprootScript(
		w.walletData.Pubkey, data.AspPubkey, uint(data.UnilateralExitDelay),
	)
	if err != nil {
		return "", "", "", err
	}

	redemptionAddr, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(vtxoTapKey),
		&netParams,
	)
	if err != nil {
		return "", "", "", err
	}

	return offchainAddr, onchainAddr.EncodeAddress(), redemptionAddr.EncodeAddress(), nil
}
