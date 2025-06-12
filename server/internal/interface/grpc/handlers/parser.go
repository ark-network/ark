package handlers

import (
	"encoding/hex"
	"fmt"
	"strings"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/bip322"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/server/internal/core/application"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
)

// From interface type to app type

func parseAddress(addr string) (*common.Address, error) {
	if len(addr) <= 0 {
		return nil, fmt.Errorf("missing address")
	}
	return common.DecodeAddress(addr)
}

func parseArkAddress(addr string) (string, error) {
	a, err := parseAddress(addr)
	if err != nil {
		return "", err
	}
	if _, err := btcutil.DecodeAddress(addr, nil); err == nil {
		return "", fmt.Errorf("must be an ark address")
	}
	return hex.EncodeToString(schnorr.SerializePubKey(a.VtxoTapKey)), nil
}

func parseIntent(intent *arkv1.Bip322Signature) (*bip322.Signature, *tree.IntentMessage, error) {
	if intent == nil {
		return nil, nil, fmt.Errorf("missing inputs")
	}
	intentSignature := intent.GetSignature()
	if len(intentSignature) <= 0 {
		return nil, nil, fmt.Errorf("missing BIP0322signature")
	}
	intentMessage := intent.GetMessage()
	if len(intentMessage) <= 0 {
		return nil, nil, fmt.Errorf("missing BIP0322 message")
	}

	signature, err := bip322.DecodeSignature(intent.GetSignature())
	if err != nil {
		return nil, nil, fmt.Errorf("invalid BIP0322 signature")
	}
	message := &tree.IntentMessage{}
	if err := message.Decode(intentMessage); err != nil {
		return nil, nil, fmt.Errorf("invalid BIP0322 message")
	}

	return signature, message, nil
}

func parseDeleteIntent(intent *arkv1.Bip322Signature) (*bip322.Signature, *tree.DeleteIntentMessage, error) {
	if intent == nil {
		return nil, nil, fmt.Errorf("missing inputs")
	}
	intentSignature := intent.GetSignature()
	if len(intentSignature) <= 0 {
		return nil, nil, fmt.Errorf("missing BIP0322signature")
	}
	intentMessage := intent.GetMessage()
	if len(intentMessage) <= 0 {
		return nil, nil, fmt.Errorf("missing BIP0322 message")
	}

	signature, err := bip322.DecodeSignature(intent.GetSignature())
	if err != nil {
		return nil, nil, fmt.Errorf("invalid BIP0322 signature")
	}
	message := &tree.DeleteIntentMessage{}
	if err := message.Decode(intentMessage); err != nil {
		return nil, nil, fmt.Errorf("invalid BIP0322 message")
	}

	return signature, message, nil
}

func parseBatchId(id string) (string, error) {
	if len(id) <= 0 {
		return "", fmt.Errorf("missing batch id")
	}
	return id, nil
}

func parseECPubkey(pubkey string) (*btcec.PublicKey, error) {
	if len(pubkey) <= 0 {
		return nil, fmt.Errorf("missing pubkey")
	}
	buf, err := hex.DecodeString(pubkey)
	if err != nil {
		return nil, fmt.Errorf("invalid pubkey format: %s", err)
	}
	if len(buf) != 33 {
		return nil, fmt.Errorf("invalid pubkey length: got %d, expeted 33", len(buf))
	}
	pk, err := btcec.ParsePubKey(buf)
	if err != nil {
		return nil, fmt.Errorf("invalid schnorr pubkey: %s", err)
	}
	return pk, nil
}

func parseNonces(nonces string) (string, error) {
	if len(nonces) <= 0 {
		return "", fmt.Errorf("missing tree nonces")
	}
	if _, err := tree.DecodeNonces(hex.NewDecoder(strings.NewReader(nonces))); err != nil {
		return "", fmt.Errorf("invalid tree nonces: %s", err)
	}
	return nonces, nil
}

func parseSignatures(sigs string) (string, error) {
	if len(sigs) <= 0 {
		return "", fmt.Errorf("missing tree signatures")
	}
	if _, err := tree.DecodeSignatures(hex.NewDecoder(strings.NewReader(sigs))); err != nil {
		return "", fmt.Errorf("invalid tree signatures: %s", err)
	}
	return sigs, nil
}

func parseCheckpointTxs(txs []string) ([]string, error) {
	if len(txs) <= 0 {
		return nil, fmt.Errorf("missing checkpoint txs")
	}
	for _, tx := range txs {
		if _, err := parseTx(tx, "checkpoint"); err != nil {
			return nil, err
		}
	}
	return txs, nil
}

func parseVirtualTx(tx string) (string, error) {
	return parseTx(tx, "virtual")
}

func parseTx(tx, txType string) (string, error) {
	if len(tx) <= 0 {
		return "", fmt.Errorf("missing %s tx", txType)
	}
	return tx, nil
}

// From app type to interface type

type vtxoList []domain.Vtxo

func (v vtxoList) toProto() []*arkv1.Vtxo {
	list := make([]*arkv1.Vtxo, 0, len(v))
	for _, vv := range v {
		list = append(list, &arkv1.Vtxo{
			Outpoint: &arkv1.Outpoint{
				Txid: vv.Txid,
				Vout: vv.VOut,
			},
			Amount:         vv.Amount,
			CommitmentTxid: vv.CommitmentTxid,
			Spent:          vv.Spent,
			ExpiresAt:      vv.ExpireAt,
			SpentBy:        vv.SpentBy,
			Swept:          vv.Swept,
			Preconfirmed:   len(vv.RedeemTx) > 0,
			Pubkey:         vv.PubKey,
			CreatedAt:      vv.CreatedAt,
		})
	}

	return list
}

type connectorsIndex map[string]domain.Outpoint

func (c connectorsIndex) toProto() map[string]*arkv1.Outpoint {
	proto := make(map[string]*arkv1.Outpoint)
	for vtxo, outpoint := range c {
		proto[vtxo] = &arkv1.Outpoint{
			Txid: outpoint.Txid,
			Vout: outpoint.VOut,
		}
	}
	return proto
}

type roundTxEvent application.CommitmentTransactionEvent

func (e roundTxEvent) toProto() *arkv1.ArkTransaction {
	return &arkv1.ArkTransaction{
		Txid:           e.Txid,
		SpentVtxos:     vtxoList(e.SpentVtxos).toProto(),
		SpendableVtxos: vtxoList(e.SpendableVtxos).toProto(),
		Hex:            e.TxHex,
	}
}

type redeemTxEvent application.VirtualTransactionEvent

func (e redeemTxEvent) toProto() *arkv1.ArkTransaction {
	return &arkv1.ArkTransaction{
		Txid:           e.Txid,
		SpentVtxos:     vtxoList(e.SpentVtxos).toProto(),
		SpendableVtxos: vtxoList(e.SpendableVtxos).toProto(),
		Hex:            e.TxHex,
	}
}

type intentsInfo []application.IntentInfo

func (i intentsInfo) toProto() []*arkv1.IntentInfo {
	list := make([]*arkv1.IntentInfo, 0, len(i))
	for _, req := range i {
		receivers := make([]*arkv1.Output, 0, len(req.Receivers))
		for _, receiver := range req.Receivers {
			receivers = append(receivers, &arkv1.Output{
				Address: receiver.Address,
				Amount:  receiver.Amount,
			})
		}

		inputs := make([]*arkv1.IntentInput, 0, len(req.Inputs))
		for _, input := range req.Inputs {
			inputs = append(inputs, &arkv1.IntentInput{
				Txid:   input.Txid,
				Vout:   input.VOut,
				Amount: input.Amount,
			})
		}

		boardingInputs := make([]*arkv1.IntentInput, 0, len(req.BoardingInputs))
		for _, input := range req.BoardingInputs {
			boardingInputs = append(boardingInputs, &arkv1.IntentInput{
				Txid:   input.Txid,
				Vout:   input.VOut,
				Amount: input.Amount,
			})
		}

		list = append(list, &arkv1.IntentInfo{
			Id:                  req.Id,
			CreatedAt:           req.CreatedAt.Unix(),
			Receivers:           receivers,
			Inputs:              inputs,
			BoardingInputs:      boardingInputs,
			SigningType:         req.SigningType,
			CosignersPublicKeys: req.Cosigners,
		})
	}
	return list
}

// convert sats to string BTC
func convertSatsToBTCStr(sats uint64) string {
	btc := float64(sats) * 1e-8
	return fmt.Sprintf("%.8f", btc)
}
