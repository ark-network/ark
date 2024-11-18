package oceanwallet

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	pb "github.com/ark-network/ark/api-spec/protobuf/gen/ocean/v1"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/server/internal/core/ports"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/vulpemventures/go-elements/elementsutil"
	"github.com/vulpemventures/go-elements/psetv2"
)

const (
	zero32 = "0000000000000000000000000000000000000000000000000000000000000000"
)

func (s *service) SignTransaction(
	ctx context.Context, pset string, finalizeAndExtractRawTx bool,
) (string, error) {
	res, err := s.txClient.SignPset(ctx, &pb.SignPsetRequest{
		Pset: pset,
	})
	if err != nil {
		return "", err
	}
	signedPset := res.GetPset()

	if !finalizeAndExtractRawTx {
		return signedPset, nil
	}

	ptx, err := psetv2.NewPsetFromBase64(signedPset)
	if err != nil {
		return "", err
	}

	for i, in := range ptx.Inputs {
		if in.WitnessUtxo == nil {
			return "", fmt.Errorf("missing witness utxo, cannot finalize tx")
		}

		if len(in.TapLeafScript) > 0 {
			tapLeaf := in.TapLeafScript[0]

			closure, err := tree.DecodeClosure(tapLeaf.Script)
			if err != nil {
				return "", err
			}

			switch c := closure.(type) {
			case *tree.MultisigClosure:
				asp := schnorr.SerializePubKey(c.AspPubkey)
				owner := schnorr.SerializePubKey(c.Pubkey)

				witness := make([][]byte, 4)
				for _, sig := range in.TapScriptSig {
					if bytes.Equal(sig.PubKey, owner) {
						witness[0] = sig.Signature
						continue
					}

					if bytes.Equal(sig.PubKey, asp) {
						witness[1] = sig.Signature
					}
				}

				witness[2] = tapLeaf.Script

				controlBlock, err := tapLeaf.ControlBlock.ToBytes()
				if err != nil {
					return "", err
				}

				witness[3] = controlBlock

				var witnessBuf bytes.Buffer

				if err := psbt.WriteTxWitness(&witnessBuf, witness); err != nil {
					return "", err
				}

				ptx.Inputs[i].FinalScriptWitness = witnessBuf.Bytes()
				continue
			default:
				return "", fmt.Errorf("unexpected closure type %T", c)
			}
		}

		if err := psetv2.Finalize(ptx, i); err != nil {
			return "", fmt.Errorf("failed to finalize signed pset: %s", err)
		}
	}

	extractedTx, err := psetv2.Extract(ptx)
	if err != nil {
		return "", fmt.Errorf("failed to extract signed pset: %s", err)
	}

	txHex, err := extractedTx.ToHex()
	if err != nil {
		return "", fmt.Errorf("failed to convert extracted tx to hex: %s", err)
	}

	return txHex, nil
}

func (s *service) SelectUtxos(ctx context.Context, asset string, amount uint64) ([]ports.TxInput, uint64, error) {
	res, err := s.txClient.SelectUtxos(ctx, &pb.SelectUtxosRequest{
		AccountName:  arkAccount,
		TargetAsset:  asset,
		TargetAmount: amount,
	})
	if err != nil {
		return nil, 0, err
	}

	inputs := make([]ports.TxInput, 0, len(res.GetUtxos()))
	for _, utxo := range res.GetUtxos() {
		// check that the utxos are not confidential
		if utxo.GetAssetBlinder() != zero32 || utxo.GetValueBlinder() != zero32 {
			return nil, 0, fmt.Errorf("utxo is confidential")
		}

		inputs = append(inputs, utxo)
	}

	return inputs, res.GetChange(), nil
}

func (s *service) BroadcastTransaction(
	ctx context.Context, txHex string,
) (string, error) {
	res, err := s.txClient.BroadcastTransaction(
		ctx, &pb.BroadcastTransactionRequest{
			TxHex: txHex,
		},
	)
	if err != nil {
		if strings.Contains(err.Error(), "non-BIP68-final") {
			return "", ports.ErrNonFinalBIP68
		}

		return "", err
	}
	return res.GetTxid(), nil
}

func (s *service) IsTransactionConfirmed(
	ctx context.Context, txid string,
) (bool, int64, int64, error) {
	_, isConfirmed, blockheight, blocktime, err := s.getTransaction(ctx, txid)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "missing transaction") {
			return isConfirmed, 0, 0, nil
		}
		return false, 0, 0, err
	}

	return isConfirmed, blockheight, blocktime, nil
}
func (s *service) WaitForSync(ctx context.Context, txid string) error {
	for {
		time.Sleep(5 * time.Second)
		_, _, _, _, err := s.getTransaction(ctx, txid)
		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "missing transaction") {
				continue
			}
			return err
		}
		break
	}
	return nil
}

func (s *service) SignTransactionTapscript(ctx context.Context, b64 string, indexes []int) (string, error) {
	pset, err := psetv2.NewPsetFromBase64(b64)
	if err != nil {
		return "", err
	}

	if indexes == nil {
		for i := 0; i < len(pset.Inputs); i++ {
			indexes = append(indexes, i)
		}
	}

	key, masterKey, err := s.getPubkey(ctx)
	if err != nil {
		return "", err
	}

	fingerprint := binary.LittleEndian.Uint32(masterKey.FingerPrint)
	extendedKey, err := masterKey.Serialize()
	if err != nil {
		return "", err
	}

	pset.Global.Xpubs = []psetv2.Xpub{{
		ExtendedKey:       extendedKey[:len(extendedKey)-4],
		MasterFingerprint: fingerprint,
		DerivationPath:    derivationPath,
	}}

	updater, err := psetv2.NewUpdater(pset)
	if err != nil {
		return "", err
	}

	bip32derivation := psetv2.DerivationPathWithPubKey{
		PubKey:               key.SerializeCompressed(),
		MasterKeyFingerprint: fingerprint,
		Bip32Path:            derivationPath,
	}

	for _, i := range indexes {
		if len(pset.Inputs[i].TapLeafScript) == 0 {
			return "", fmt.Errorf("no tap leaf script found for input %d", i)
		}

		leafHash := pset.Inputs[i].TapLeafScript[0].TapHash()

		if err := updater.AddInTapBip32Derivation(i, psetv2.TapDerivationPathWithPubKey{
			DerivationPathWithPubKey: bip32derivation,
			LeafHashes:               [][]byte{leafHash[:]},
		}); err != nil {
			return "", err
		}

		if err := updater.AddInSighashType(i, txscript.SigHashDefault); err != nil {
			return "", err
		}
	}

	unsignedPset, err := pset.ToBase64()
	if err != nil {
		return "", err
	}

	signedPset, err := s.txClient.SignPsetWithSchnorrKey(ctx, &pb.SignPsetWithSchnorrKeyRequest{
		Tx:          unsignedPset,
		SighashType: uint32(txscript.SigHashDefault),
	})
	if err != nil {
		return "", err
	}

	return signedPset.GetSignedTx(), nil
}

func (s *service) LockConnectorUtxos(ctx context.Context, utxos []ports.TxOutpoint) error {
	pbUtxos := make([]*pb.Input, 0, len(utxos))
	for _, utxo := range utxos {
		pbUtxos = append(pbUtxos, &pb.Input{
			Txid:  utxo.GetTxid(),
			Index: utxo.GetIndex(),
		})
	}

	_, err := s.txClient.LockUtxos(ctx, &pb.LockUtxosRequest{
		AccountName: connectorAccount,
		Utxos:       pbUtxos,
	})
	return err
}

var minRate = chainfee.SatPerKVByte(0.2 * 1000)

func (s *service) MinRelayFeeRate(ctx context.Context) chainfee.SatPerKVByte {
	return minRate
}

func (s *service) MinRelayFee(ctx context.Context, vbytes uint64) (uint64, error) {
	feeRate := 0.2
	fee := uint64(float64(vbytes) * feeRate)
	return fee, nil
}

func (s *service) EstimateFees(
	ctx context.Context, pset string,
) (uint64, error) {
	tx, err := psetv2.NewPsetFromBase64(pset)
	if err != nil {
		return 0, err
	}

	inputs := make([]*pb.Input, 0, len(tx.Inputs))
	outputs := make([]*pb.Output, 0, len(tx.Outputs))

	for _, in := range tx.Inputs {
		pbInput := &pb.Input{
			Txid:  chainhash.Hash(in.PreviousTxid).String(),
			Index: in.PreviousTxIndex,
		}

		if len(in.TapLeafScript) == 1 {
			isSweep, err := (&tree.CSVSigClosure{}).Decode(in.TapLeafScript[0].Script)
			if err != nil {
				return 0, err
			}

			if isSweep {
				pbInput.WitnessSize = 64
				pbInput.ScriptsigSize = 0
			}
		} else {
			if in.WitnessUtxo == nil {
				return 0, fmt.Errorf("missing witness utxo, cannot estimate fees")
			}

			pbInput.Script = hex.EncodeToString(in.WitnessUtxo.Script)
		}

		inputs = append(inputs, pbInput)
	}

	for _, out := range tx.Outputs {
		outputs = append(outputs, &pb.Output{
			Asset: elementsutil.AssetHashFromBytes(
				append([]byte{0x01}, out.Asset...),
			),
			Amount: out.Value,
			Script: hex.EncodeToString(out.Script),
		})
	}

	fee, err := s.txClient.EstimateFees(
		ctx,
		&pb.EstimateFeesRequest{
			Inputs:  inputs,
			Outputs: outputs,
		},
	)
	if err != nil {
		return 0, fmt.Errorf("failed to estimate fees: %s", err)
	}

	// we add 5 sats in order to avoid min-relay-fee not met errors
	return fee.GetFeeAmount() + 5, nil
}

func (s *service) GetTransaction(ctx context.Context, txid string) (string, error) {
	txHex, _, _, _, err := s.getTransaction(ctx, txid)
	if err != nil {
		return "", err
	}

	return txHex, nil
}

func (s *service) getTransaction(
	ctx context.Context, txid string,
) (string, bool, int64, int64, error) {
	res, err := s.txClient.GetTransaction(ctx, &pb.GetTransactionRequest{
		Txid: txid,
	})
	if err != nil {
		return "", false, 0, 0, err
	}

	if res.GetBlockDetails().GetTimestamp() > 0 {
		return res.GetTxHex(), true, int64(res.GetBlockDetails().GetHeight()), res.BlockDetails.GetTimestamp(), nil
	}

	// if not confirmed, we return now + 1 min to estimate the next blocktime
	return res.GetTxHex(), false, 0, time.Now().Add(time.Minute).Unix(), nil
}
