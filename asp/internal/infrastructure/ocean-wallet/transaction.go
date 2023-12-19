package oceanwallet

import (
	"context"
	"encoding/binary"
	"fmt"

	pb "github.com/ark-network/ark/api-spec/protobuf/gen/ocean/v1"
	"github.com/ark-network/ark/internal/core/ports"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/vulpemventures/go-elements/psetv2"
	"github.com/vulpemventures/go-elements/transaction"
)

const msatsPerByte = 110

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

	ptx, _ := psetv2.NewPsetFromBase64(signedPset)
	if err := psetv2.MaybeFinalizeAll(ptx); err != nil {
		return "", fmt.Errorf("failed to finalize signed pset: %s", err)
	}
	return ptx.ToBase64()
}

func (s *service) Transfer(
	ctx context.Context, outs []ports.TxOutput,
) (string, error) {
	res, err := s.txClient.Transfer(ctx, &pb.TransferRequest{
		AccountName:      accountLabel,
		Receivers:        outputList(outs).toProto(),
		MillisatsPerByte: msatsPerByte,
	})
	if err != nil {
		return "", err
	}
	return res.GetTxHex(), nil
}

func (s *service) GetTransaction(
	ctx context.Context, txid string,
) (string, uint64, error) {
	res, err := s.txClient.GetTransaction(ctx, &pb.GetTransactionRequest{
		Txid: txid,
	})
	if err != nil {
		return "", 0, err
	}
	return res.GetTxHex(), uint64(res.GetBlockDetails().Timestamp), nil
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
		return "", err
	}
	return res.GetTxid(), nil
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

		prevoutHex, _, err := s.GetTransaction(
			ctx,
			chainhash.Hash(pset.Inputs[i].PreviousTxid).String(),
		)
		if err != nil {
			return "", err
		}

		prevoutTx, err := transaction.NewTxFromHex(prevoutHex)
		if err != nil {
			return "", err
		}

		prevoutOutput := prevoutTx.Outputs[pset.Inputs[i].PreviousTxIndex]

		if err := updater.AddInWitnessUtxo(i, prevoutOutput); err != nil {
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

type outputList []ports.TxOutput

func (l outputList) toProto() []*pb.Output {
	list := make([]*pb.Output, 0, len(l))
	for _, out := range l {
		list = append(list, &pb.Output{
			Amount: out.GetAmount(),
			Script: out.GetScript(),
			Asset:  out.GetAsset(),
		})
	}
	return list
}
