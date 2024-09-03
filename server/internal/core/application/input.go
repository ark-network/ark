package application

import (
	"fmt"

	"github.com/ark-network/ark/common/descriptor"
	"github.com/ark-network/ark/server/internal/core/domain"
)

type Input struct {
	Txid       string
	Index      uint32
	Descriptor *string
}

type BoardingInput struct {
	Input
	descriptor.TaprootDescriptor
}

func (i Input) IsVtxo() bool {
	return i.Descriptor == nil
}

func (i Input) VtxoKey() domain.VtxoKey {
	return domain.VtxoKey{
		Txid: i.Txid,
		VOut: i.Index,
	}
}

func (i Input) AsBoardingInput() (BoardingInput, error) {
	if i.Descriptor == nil {
		return BoardingInput{}, fmt.Errorf("input is not a boarding input")
	}

	tapDescriptor, err := descriptor.ParseTaprootDescriptor(*i.Descriptor)
	if err != nil {
		return BoardingInput{}, err
	}

	return BoardingInput{i, tapDescriptor}, nil
}
