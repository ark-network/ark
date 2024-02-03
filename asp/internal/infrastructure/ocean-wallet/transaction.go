package oceanwallet

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	pb "github.com/ark-network/ark/api-spec/protobuf/gen/ocean/v1"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/internal/core/ports"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/vulpemventures/go-elements/elementsutil"
	"github.com/vulpemventures/go-elements/psetv2"
)

const (
	zero32 = "0000000000000000000000000000000000000000000000000000000000000000"
)

var (
	NonBIP68Final = fmt.Errorf("non-BIP68-final")
)

func (s *service) SignPset(
	ctx context.Context, pset string, extractRawTx bool,
) (string, error) {
	res, err := s.txClient.SignPset(ctx, &pb.SignPsetRequest{
		Pset: pset,
	})
	if err != nil {
		return "", err
	}
	signedPset := res.GetPset()

	if !extractRawTx {
		return signedPset, nil
	}

	ptx, err := psetv2.NewPsetFromBase64(signedPset)
	if err != nil {
		return "", err
	}

	if err := psetv2.MaybeFinalizeAll(ptx); err != nil {
		return "", fmt.Errorf("failed to finalize signed pset: %s", err)
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
		AccountName:  accountLabel,
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

func (s *service) GetTransaction(
	ctx context.Context, txid string,
) (string, int64, error) {
	res, err := s.txClient.GetTransaction(ctx, &pb.GetTransactionRequest{
		Txid: txid,
	})
	if err != nil {
		return "", 0, err
	}

	if res.GetBlockDetails().GetTimestamp() > 0 {
		return res.GetTxHex(), res.BlockDetails.GetTimestamp(), nil
	}

	// if not confirmed, we return now + 30 secs to estimate the next blocktime
	return res.GetTxHex(), time.Now().Unix() + 30, nil
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
			return "", NonBIP68Final
		}

		return "", err
	}
	return res.GetTxid(), nil
}

func (s *service) IsTransactionPublished(
	ctx context.Context, txid string,
) (bool, int64, error) {
	_, blocktime, err := s.GetTransaction(ctx, txid)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "missing transaction") {
			return false, 0, nil
		}
		return false, 0, err
	}

	return true, blocktime, nil
}

func (s *service) SignPsetWithKey(ctx context.Context, b64 string, indexes []int) (string, error) {
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
			isSweep, _, _, err := tree.DecodeSweepScript(in.TapLeafScript[0].Script)
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
