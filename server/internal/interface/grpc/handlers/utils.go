package handlers

import (
	"encoding/hex"
	"fmt"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/server/internal/core/application"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func parseAddress(addr string) (string, *secp256k1.PublicKey, *secp256k1.PublicKey, error) {
	if len(addr) <= 0 {
		return "", nil, nil, fmt.Errorf("missing address")
	}
	return common.DecodeAddress(addr)
}

func parseInputs(ins []*arkv1.Input) ([]application.Input, error) {
	if len(ins) <= 0 {
		return nil, fmt.Errorf("missing inputs")
	}

	inputs := make([]application.Input, 0, len(ins))
	for _, input := range ins {

		vtxoKey := domain.VtxoKey{
			Txid: input.GetTxid(),
			VOut: input.GetVout(),
		}

		reverseBoardingKey := input.GetReverseBoardingPubkey()
		if reverseBoardingKey == "" {
			inputs = append(inputs, application.VtxoInput{
				VtxoKey: vtxoKey,
			})
			continue
		}

		ownerPubkeyBytes, err := hex.DecodeString(reverseBoardingKey)
		if err != nil {
			return nil, fmt.Errorf("invalid reverse boarding pubkey")
		}

		ownerPubkey, err := secp256k1.ParsePubKey(ownerPubkeyBytes)
		if err != nil {
			return nil, fmt.Errorf("invalid reverse boarding pubkey")
		}

		inputs = append(inputs, application.ReverseBoardingInput{
			VtxoKey:        vtxoKey,
			OwnerPublicKey: ownerPubkey,
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
		if len(out.GetAddress()) <= 0 {
			return nil, fmt.Errorf("missing output address")
		}
		var pubkey, addr string
		_, pk, _, err := common.DecodeAddress(out.GetAddress())
		if err != nil {
			addr = out.GetAddress()
		}
		if pk != nil {
			pubkey = hex.EncodeToString(pk.SerializeCompressed())
		}
		receivers = append(receivers, domain.Receiver{
			Pubkey:         pubkey,
			Amount:         out.GetAmount(),
			OnchainAddress: addr,
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
