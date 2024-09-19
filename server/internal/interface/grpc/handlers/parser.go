package handlers

import (
	"fmt"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/ark-network/ark/server/internal/core/ports"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// From interface type to app type

func parseAddress(addr string) (string, *secp256k1.PublicKey, *secp256k1.PublicKey, error) {
	if len(addr) <= 0 {
		return "", nil, nil, fmt.Errorf("missing address")
	}
	return common.DecodeAddress(addr)
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
			Descriptor: input.GetDescriptor_(),
		})
	}

	return inputs, nil
}

func parseReceivers(outs []*arkv1.Output) ([]domain.Receiver, error) {
	receivers := make([]domain.Receiver, 0, len(outs))
	for _, out := range outs {
		if out.GetAmount() == 0 {
			return nil, fmt.Errorf("missing output amount")
		}
		if len(out.GetAddress()) <= 0 && len(out.GetDescriptor_()) <= 0 {
			return nil, fmt.Errorf("missing output destination")
		}

		receivers = append(receivers, domain.Receiver{
			Descriptor:     out.GetDescriptor_(),
			Amount:         out.GetAmount(),
			OnchainAddress: out.GetAddress(),
		})
	}
	return receivers, nil
}

// From app typeto interface type

type vtxoList []domain.Vtxo

func (v vtxoList) toProto() []*arkv1.Vtxo {
	list := make([]*arkv1.Vtxo, 0, len(v))
	for _, vv := range v {
		var pendingData *arkv1.PendingPayment
		if vv.AsyncPayment != nil {
			pendingData = &arkv1.PendingPayment{
				RedeemTx:                vv.AsyncPayment.RedeemTx,
				UnconditionalForfeitTxs: vv.AsyncPayment.UnconditionalForfeitTxs,
			}
		}
		list = append(list, &arkv1.Vtxo{
			Outpoint: &arkv1.Outpoint{
				Txid: vv.Txid,
				Vout: vv.VOut,
			},
			Descriptor_: vv.Descriptor,
			Amount:      vv.Amount,
			PoolTxid:    vv.PoolTx,
			Spent:       vv.Spent,
			ExpireAt:    vv.ExpireAt,
			SpentBy:     vv.SpentBy,
			Swept:       vv.Swept,
			PendingData: pendingData,
			Pending:     vv.Pending,
		})
	}

	return list
}

type congestionTree tree.CongestionTree

func (t congestionTree) toProto() *arkv1.Tree {
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
