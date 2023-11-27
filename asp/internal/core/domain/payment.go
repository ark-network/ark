package domain

import (
	"fmt"

	"github.com/google/uuid"
)

type Payment struct {
	Id        string
	Inputs    []Vtxo
	Receivers []Receiver
}

func NewPayment(inputs []Vtxo) Payment {
	return Payment{
		Id:     uuid.New().String(),
		Inputs: inputs,
	}
}

func (p Payment) TotOutputAmount() uint64 {
	tot := uint64(0)
	for _, r := range p.Receivers {
		tot += r.Amount
	}
	return tot
}

func (p Payment) validate(ignoreOuts bool) error {
	if len(p.Id) <= 0 {
		return fmt.Errorf("missing id")
	}
	if len(p.Inputs) <= 0 {
		return fmt.Errorf("missing inputs")
	}
	if !ignoreOuts && len(p.Receivers) <= 0 {
		return fmt.Errorf("missing outputs")
	}
	return nil
}

type VtxoKey struct {
	Txid string
	VOut uint32
}

type Receiver struct {
	Pubkey string
	Amount uint64
}

type Vtxo struct {
	VtxoKey
	Receiver
	Spent bool
}
