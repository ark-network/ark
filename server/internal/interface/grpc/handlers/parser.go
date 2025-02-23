package handlers

import (
	"encoding/hex"
	"fmt"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/note"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/server/internal/core/application"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/ark-network/ark/server/internal/core/ports"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
)

// From interface type to app type

func parseAddress(addr string) (*common.Address, error) {
	if len(addr) <= 0 {
		return nil, fmt.Errorf("missing address")
	}
	return common.DecodeAddress(addr)
}

func parseNotes(notes []string) ([]note.Note, error) {
	if len(notes) <= 0 {
		return nil, fmt.Errorf("missing notes")
	}

	notesParsed := make([]note.Note, 0, len(notes))
	for _, noteStr := range notes {
		n, err := note.NewFromString(noteStr)
		if err != nil {
			return nil, fmt.Errorf("invalid note: %s", err)
		}

		notesParsed = append(notesParsed, *n)
	}

	return notesParsed, nil
}

func parseInputs(ins []*arkv1.Input) ([]ports.Input, error) {
	if len(ins) <= 0 {
		return nil, fmt.Errorf("missing inputs")
	}

	inputs := make([]ports.Input, 0, len(ins))
	for _, input := range ins {
		inputs = append(inputs, ports.Input{
			VtxoKey: domain.VtxoKey{
				Txid: input.GetOutpoint().GetTxid(),
				VOut: input.GetOutpoint().GetVout(),
			},
			Tapscripts: input.GetTapscripts().GetScripts(),
		})
	}

	return inputs, nil
}

func parseReceiver(out *arkv1.Output) (domain.Receiver, error) {
	decodedAddr, err := common.DecodeAddress(out.GetAddress())
	if err != nil {
		// onchain address
		return domain.Receiver{
			Amount:         out.GetAmount(),
			OnchainAddress: out.GetAddress(),
		}, nil
	}

	return domain.Receiver{
		Amount: out.GetAmount(),
		PubKey: hex.EncodeToString(schnorr.SerializePubKey(decodedAddr.VtxoTapKey)),
	}, nil
}

func parseReceivers(outs []*arkv1.Output) ([]domain.Receiver, error) {
	receivers := make([]domain.Receiver, 0, len(outs))
	for _, out := range outs {
		if out.GetAmount() == 0 {
			return nil, fmt.Errorf("missing output amount")
		}
		if len(out.GetAddress()) <= 0 {
			return nil, fmt.Errorf("missing output destination")
		}

		rcv, err := parseReceiver(out)
		if err != nil {
			return nil, err
		}

		receivers = append(receivers, rcv)
	}
	return receivers, nil
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
			Amount:    vv.Amount,
			RoundTxid: vv.RoundTxid,
			Spent:     vv.Spent,
			ExpireAt:  vv.ExpireAt,
			SpentBy:   vv.SpentBy,
			Swept:     vv.Swept,
			RedeemTx:  vv.RedeemTx,
			IsPending: len(vv.RedeemTx) > 0,
			Pubkey:    vv.PubKey,
			CreatedAt: vv.CreatedAt,
		})
	}

	return list
}

type vtxoKeyList []domain.VtxoKey

func (v vtxoKeyList) toProto() []*arkv1.Outpoint {
	list := make([]*arkv1.Outpoint, 0, len(v))
	for _, vtxoKey := range v {
		list = append(list, &arkv1.Outpoint{
			Txid: vtxoKey.Txid,
			Vout: vtxoKey.VOut,
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

type vtxoTree tree.TxTree

func (t vtxoTree) toProto() *arkv1.Tree {
	levels := make([]*arkv1.TreeLevel, 0, len(t))
	for _, level := range t {
		levelProto := &arkv1.TreeLevel{
			Nodes: make([]*arkv1.Node, 0, len(level)),
		}

		for _, node := range level {
			levelProto.Nodes = append(levelProto.Nodes, &arkv1.Node{
				Txid:       node.Txid,
				Tx:         node.Tx,
				ParentTxid: node.ParentTxid,
			})
		}

		levels = append(levels, levelProto)
	}
	return &arkv1.Tree{
		Levels: levels,
	}
}

type stage domain.Stage

func (s stage) toProto() arkv1.RoundStage {
	if s.Failed {
		return arkv1.RoundStage_ROUND_STAGE_FAILED
	}

	switch s.Code {
	case domain.RegistrationStage:
		return arkv1.RoundStage_ROUND_STAGE_REGISTRATION
	case domain.FinalizationStage:
		if s.Ended {
			return arkv1.RoundStage_ROUND_STAGE_FINALIZED
		}
		return arkv1.RoundStage_ROUND_STAGE_FINALIZATION
	default:
		return arkv1.RoundStage_ROUND_STAGE_UNSPECIFIED
	}
}

type roundTxEvent application.RoundTransactionEvent

func (e roundTxEvent) toProto() *arkv1.RoundTransaction {
	return &arkv1.RoundTransaction{
		Txid:                 e.RoundTxid,
		SpentVtxos:           vtxoList(e.SpentVtxos).toProto(),
		SpendableVtxos:       vtxoList(e.SpendableVtxos).toProto(),
		ClaimedBoardingUtxos: vtxoKeyList(e.ClaimedBoardingInputs).toProto(),
	}
}

type redeemTxEvent application.RedeemTransactionEvent

func (e redeemTxEvent) toProto() *arkv1.RedeemTransaction {
	return &arkv1.RedeemTransaction{
		Txid:           e.RedeemTxid,
		SpentVtxos:     vtxoList(e.SpentVtxos).toProto(),
		SpendableVtxos: vtxoList(e.SpendableVtxos).toProto(),
	}
}

func parseSignedVtxoOutpoints(signedVtxoOutpoints []*arkv1.SignedVtxoOutpoint) ([]application.SignedVtxoOutpoint, error) {
	if len(signedVtxoOutpoints) <= 0 {
		return nil, fmt.Errorf("missing signed vtxo outpoints")
	}

	parsed := make([]application.SignedVtxoOutpoint, 0, len(signedVtxoOutpoints))
	for _, signedVtxo := range signedVtxoOutpoints {
		outpoint := signedVtxo.GetOutpoint()
		if outpoint == nil {
			return nil, fmt.Errorf("missing outpoint")
		}

		txid := outpoint.GetTxid()
		if len(txid) <= 0 {
			return nil, fmt.Errorf("missing txid")
		}

		proof := signedVtxo.GetProof()
		if proof == nil {
			return nil, fmt.Errorf("missing proof")
		}

		controlBlockHex := proof.GetControlBlock()
		if len(controlBlockHex) <= 0 {
			return nil, fmt.Errorf("missing control block")
		}

		controlBlockBytes, err := hex.DecodeString(controlBlockHex)
		if err != nil {
			return nil, fmt.Errorf("invalid control block: %s", err)
		}

		controlBlock, err := txscript.ParseControlBlock(controlBlockBytes)
		if err != nil {
			return nil, fmt.Errorf("invalid control block: %s", err)
		}

		signatureHex := proof.GetSignature()
		if len(signatureHex) <= 0 {
			return nil, fmt.Errorf("missing signature")
		}

		signatureBytes, err := hex.DecodeString(signatureHex)
		if err != nil {
			return nil, fmt.Errorf("invalid signature: %s", err)
		}

		signature, err := schnorr.ParseSignature(signatureBytes)
		if err != nil {
			return nil, fmt.Errorf("invalid signature: %s", err)
		}

		scriptHex := proof.GetScript()
		if len(scriptHex) <= 0 {
			return nil, fmt.Errorf("missing script")
		}

		scriptBytes, err := hex.DecodeString(scriptHex)
		if err != nil {
			return nil, fmt.Errorf("invalid script: %s", err)
		}

		vout := outpoint.GetVout()

		parsed = append(parsed, application.SignedVtxoOutpoint{
			Outpoint: domain.VtxoKey{
				Txid: txid,
				VOut: vout,
			},
			Proof: application.OwnershipProof{
				ControlBlock: controlBlock,
				Script:       scriptBytes,
				Signature:    signature,
			},
		})
	}

	return parsed, nil
}

type txReqsInfo []application.TxRequestInfo

func (i txReqsInfo) toProto() []*arkv1.TxRequestInfo {
	list := make([]*arkv1.TxRequestInfo, 0, len(i))
	for _, req := range i {
		receivers := make([]*arkv1.Output, 0, len(req.Receivers))
		for _, receiver := range req.Receivers {
			receivers = append(receivers, &arkv1.Output{
				Address: receiver.Address,
				Amount:  receiver.Amount,
			})
		}

		inputs := make([]*arkv1.RequestInput, 0, len(req.Inputs))
		for _, input := range req.Inputs {
			inputs = append(inputs, &arkv1.RequestInput{
				Txid:   input.Txid,
				Vout:   input.VOut,
				Amount: input.Amount,
			})
		}

		boardingInputs := make([]*arkv1.RequestInput, 0, len(req.BoardingInputs))
		for _, input := range req.BoardingInputs {
			boardingInputs = append(boardingInputs, &arkv1.RequestInput{
				Txid:   input.Txid,
				Vout:   input.VOut,
				Amount: input.Amount,
			})
		}

		notes := make([]string, 0, len(req.Notes))
		for _, note := range req.Notes {
			notes = append(notes, note.String())
		}

		list = append(list, &arkv1.TxRequestInfo{
			Id:                  req.Id,
			CreatedAt:           req.CreatedAt.Unix(),
			Receivers:           receivers,
			Inputs:              inputs,
			BoardingInputs:      boardingInputs,
			Notes:               notes,
			SigningType:         req.SigningType,
			CosignersPublicKeys: req.Cosigners,
			LastPing:            req.LastPing.Unix(),
		})
	}
	return list
}

// convert sats to string BTC
func convertSatsToBTCStr(sats uint64) string {
	btc := float64(sats) * 1e-8
	return fmt.Sprintf("%.8f", btc)
}
