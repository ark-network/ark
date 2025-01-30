package singlekeywallet

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/bitcointree"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/pkg/client-sdk/explorer"
	"github.com/ark-network/ark/pkg/client-sdk/internal/utils"
	"github.com/ark-network/ark/pkg/client-sdk/types"
	"github.com/ark-network/ark/pkg/client-sdk/wallet"
	walletstore "github.com/ark-network/ark/pkg/client-sdk/wallet/singlekey/store"
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
	configStore types.ConfigStore, walletStore walletstore.WalletStore,
) (wallet.WalletService, error) {
	walletData, err := walletStore.GetWallet()
	if err != nil {
		return nil, err
	}
	return &liquidWallet{
		&singlekeyWallet{
			configStore: configStore,
			walletStore: walletStore,
			walletData:  walletData,
		},
	}, nil
}

func (w *liquidWallet) GetAddresses(
	ctx context.Context,
) ([]wallet.TapscriptsAddress, []wallet.TapscriptsAddress, []wallet.TapscriptsAddress, error) {
	offchainAddr, boardingAddr, err := w.getAddress(ctx)
	if err != nil {
		return nil, nil, nil, err
	}

	encodedOffchainAddr, err := offchainAddr.Address.Encode()
	if err != nil {
		return nil, nil, nil, err
	}

	data, err := w.configStore.GetData(ctx)
	if err != nil {
		return nil, nil, nil, err
	}

	liquidNet := utils.ToElementsNetwork(data.Network)

	vtxoP2TR, err := payment.FromTweakedKey(offchainAddr.Address.VtxoTapKey, &liquidNet, nil)
	if err != nil {
		return nil, nil, nil, err
	}

	redemptionAddr, err := vtxoP2TR.TaprootAddress()
	if err != nil {
		return nil, nil, nil, err
	}

	offchainAddrs := []wallet.TapscriptsAddress{
		{
			Tapscripts: offchainAddr.Tapscripts,
			Address:    encodedOffchainAddr,
		},
	}
	boardingAddrs := []wallet.TapscriptsAddress{
		{
			Tapscripts: boardingAddr.Tapscripts,
			Address:    boardingAddr.Address,
		},
	}

	redemptionAddrs := []wallet.TapscriptsAddress{
		{
			Tapscripts: offchainAddr.Tapscripts,
			Address:    redemptionAddr,
		},
	}

	return offchainAddrs, boardingAddrs, redemptionAddrs, nil
}

func (w *liquidWallet) NewAddress(
	ctx context.Context, _ bool,
) (*wallet.TapscriptsAddress, *wallet.TapscriptsAddress, error) {
	offchainAddr, boardingAddr, err := w.getAddress(ctx)
	if err != nil {
		return nil, nil, err
	}

	encodedOffchainAddr, err := offchainAddr.Address.Encode()
	if err != nil {
		return nil, nil, err
	}

	return &wallet.TapscriptsAddress{
			Tapscripts: offchainAddr.Tapscripts,
			Address:    encodedOffchainAddr,
		}, &wallet.TapscriptsAddress{
			Tapscripts: boardingAddr.Tapscripts,
			Address:    boardingAddr.Address,
		}, nil
}

func (w *liquidWallet) NewAddresses(
	ctx context.Context, _ bool, num int,
) ([]wallet.TapscriptsAddress, []wallet.TapscriptsAddress, error) {
	offchainAddr, boardingAddr, err := w.getAddress(ctx)
	if err != nil {
		return nil, nil, err
	}

	offchainAddrs := make([]wallet.TapscriptsAddress, 0, num)
	boardingAddrs := make([]wallet.TapscriptsAddress, 0, num)
	for i := 0; i < num; i++ {
		encodedOffchainAddr, err := offchainAddr.Address.Encode()
		if err != nil {
			return nil, nil, err
		}

		offchainAddrs = append(offchainAddrs, wallet.TapscriptsAddress{
			Tapscripts: offchainAddr.Tapscripts,
			Address:    encodedOffchainAddr,
		})
		boardingAddrs = append(boardingAddrs, wallet.TapscriptsAddress{
			Tapscripts: boardingAddr.Tapscripts,
			Address:    boardingAddr.Address,
		})
	}
	return offchainAddrs, boardingAddrs, nil
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

		if err := updater.AddInSighashType(i, txscript.SigHashDefault); err != nil {
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

	myPubkey := schnorr.SerializePubKey(s.walletData.PubKey)

	for i, input := range pset.Inputs {
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
				case *tree.CSVMultisigClosure:
					for _, key := range c.MultisigClosure.PubKeys {
						if bytes.Equal(schnorr.SerializePubKey(key), myPubkey) {
							sign = true
							break
						}
					}
				case *tree.MultisigClosure:
					for _, key := range c.PubKeys {
						if bytes.Equal(schnorr.SerializePubKey(key), myPubkey) {
							sign = true
							break
						}
					}
				case *tree.CLTVMultisigClosure:
					for _, key := range c.MultisigClosure.PubKeys {
						if bytes.Equal(schnorr.SerializePubKey(key), myPubkey) {
							sign = true
							break
						}
					}
				case *tree.ConditionMultisigClosure:
					for _, key := range c.MultisigClosure.PubKeys {
						if bytes.Equal(schnorr.SerializePubKey(key), myPubkey) {
							sign = true
							break
						}
					}
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
							PubKey:    schnorr.SerializePubKey(s.walletData.PubKey),
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

func (w *liquidWallet) SignMessage(
	ctx context.Context, message []byte,
) (string, error) {
	if w.IsLocked() {
		return "", fmt.Errorf("wallet is locked")
	}

	sig, err := schnorr.Sign(w.privateKey, message)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(sig.Serialize()), nil
}

func (w *liquidWallet) NewVtxoTreeSigner(context.Context, string) (bitcointree.SignerSession, error) {
	return nil, fmt.Errorf("not implemented")
}

func (w *liquidWallet) getAddress(
	ctx context.Context,
) (
	*addressWithTapscripts,
	*wallet.TapscriptsAddress,
	error,
) {
	if w.walletData == nil {
		return nil, nil, fmt.Errorf("wallet not initialized")
	}

	data, err := w.configStore.GetData(ctx)
	if err != nil {
		return nil, nil, err
	}

	liquidNet := utils.ToElementsNetwork(data.Network)

	vtxoScript := tree.NewDefaultVtxoScript(
		w.walletData.PubKey,
		data.ServerPubKey,
		data.UnilateralExitDelay,
	)

	vtxoTapKey, _, err := vtxoScript.TapTree()
	if err != nil {
		return nil, nil, err
	}

	offchainAddr := &common.Address{
		HRP:        data.Network.Addr,
		Server:     data.ServerPubKey,
		VtxoTapKey: vtxoTapKey,
	}

	boardingVtxoScript := tree.NewDefaultVtxoScript(
		w.walletData.PubKey,
		data.ServerPubKey,
		common.RelativeLocktime{
			Type:  data.UnilateralExitDelay.Type,
			Value: data.UnilateralExitDelay.Value * 2,
		},
	)

	boardingTapKey, _, err := boardingVtxoScript.TapTree()
	if err != nil {
		return nil, nil, err
	}

	p2tr, err := payment.FromTweakedKey(boardingTapKey, &liquidNet, nil)
	if err != nil {
		return nil, nil, err
	}

	boardingAddr, err := p2tr.TaprootAddress()
	if err != nil {
		return nil, nil, err
	}

	tapscripts, err := vtxoScript.Encode()
	if err != nil {
		return nil, nil, err
	}

	boardingTapscripts, err := boardingVtxoScript.Encode()
	if err != nil {
		return nil, nil, err
	}

	return &addressWithTapscripts{
			Address:    *offchainAddr,
			Tapscripts: tapscripts,
		}, &wallet.TapscriptsAddress{
			Tapscripts: boardingTapscripts,
			Address:    boardingAddr,
		}, nil
}
