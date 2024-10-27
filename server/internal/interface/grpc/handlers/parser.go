package handlers

import (
	"encoding/hex"
	"fmt"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/common/voucher"
	"github.com/ark-network/ark/server/internal/core/application"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/ark-network/ark/server/internal/core/ports"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

// From interface type to app type

func parseAddress(addr string) (*common.Address, error) {
	if len(addr) <= 0 {
		return nil, fmt.Errorf("missing address")
	}
	return common.DecodeAddress(addr)
}

func parseAsyncPaymentInputs(ins []*arkv1.AsyncPaymentInput) ([]application.AsyncPaymentInput, error) {
	if len(ins) <= 0 {
		return nil, fmt.Errorf("missing inputs")
	}

	inputs := make([]application.AsyncPaymentInput, 0, len(ins))
	for _, input := range ins {
		forfeitLeafHash, err := chainhash.NewHashFromStr(input.GetForfeitLeafHash())
		if err != nil {
			return nil, fmt.Errorf("invalid forfeit leaf hash: %s", err)
		}

		inputs = append(inputs, application.AsyncPaymentInput{
			Input: ports.Input{
				VtxoKey: domain.VtxoKey{
					Txid: input.GetInput().GetOutpoint().GetTxid(),
					VOut: input.GetInput().GetOutpoint().GetVout(),
				},
				Descriptor: input.GetInput().GetDescriptor_(),
			},
			ForfeitLeafHash: *forfeitLeafHash,
		})
	}

	return inputs, nil
}

func parseVouchers(vouchers []string) ([]voucher.Voucher, error) {
	if len(vouchers) <= 0 {
		return nil, fmt.Errorf("missing vouchers")
	}

	vouchersParsed := make([]voucher.Voucher, 0, len(vouchers))
	for _, voucherStr := range vouchers {
		v, err := voucher.NewFromString(voucherStr)
		if err != nil {
			return nil, fmt.Errorf("invalid voucher: %s", err)
		}

		vouchersParsed = append(vouchersParsed, *v)
	}

	return vouchersParsed, nil
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
		Pubkey: hex.EncodeToString(schnorr.SerializePubKey(decodedAddr.VtxoTapKey)),
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
			Pending:   vv.Pending,
			Pubkey:    vv.Pubkey,
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
