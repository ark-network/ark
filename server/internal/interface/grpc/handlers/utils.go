package handlers

import (
	"fmt"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/ark-network/ark/server/internal/core/ports"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

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
			Descriptor:   input.GetDescriptor_(),
			SignerPubkey: input.GetSigningPubkey(),
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

func toRoundStage(stage domain.Stage) arkv1.RoundStage {
	if stage.Failed {
		return arkv1.RoundStage_ROUND_STAGE_FAILED
	}

	switch stage.Code {
	case domain.RegistrationStage:
		return arkv1.RoundStage_ROUND_STAGE_REGISTRATION
	case domain.FinalizationStage:
		if stage.Ended {
			return arkv1.RoundStage_ROUND_STAGE_FINALIZED
		}
		return arkv1.RoundStage_ROUND_STAGE_FINALIZATION
	default:
		return arkv1.RoundStage_ROUND_STAGE_UNSPECIFIED
	}
}
