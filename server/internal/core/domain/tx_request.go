package domain

import (
	"fmt"

	"github.com/google/uuid"
)

type TxRequest struct {
	Id        string
	Inputs    []Vtxo
	Receivers []Receiver
}

func NewTxRequest(inputs []Vtxo) (*TxRequest, error) {
	request := &TxRequest{
		Id:     uuid.New().String(),
		Inputs: inputs,
	}
	if err := request.validate(true); err != nil {
		return nil, err
	}
	return request, nil
}

func (r *TxRequest) AddReceivers(receivers []Receiver) (err error) {
	if r.Receivers == nil {
		r.Receivers = make([]Receiver, 0)
	}
	r.Receivers = append(r.Receivers, receivers...)
	defer func() {
		if err != nil {
			r.Receivers = r.Receivers[:len(r.Receivers)-len(receivers)]
		}
	}()
	err = r.validate(false)
	return
}

func (r TxRequest) TotalInputAmount() uint64 {
	tot := uint64(0)
	for _, in := range r.Inputs {
		tot += in.Amount
	}
	return tot
}

func (r TxRequest) TotalOutputAmount() uint64 {
	tot := uint64(0)
	for _, r := range r.Receivers {
		tot += r.Amount
	}
	return tot
}

func (r TxRequest) validate(ignoreOuts bool) error {
	if len(r.Id) <= 0 {
		return fmt.Errorf("missing id")
	}
	if ignoreOuts {
		return nil
	}

	if len(r.Receivers) <= 0 {
		return fmt.Errorf("missing outputs")
	}
	for _, r := range r.Receivers {
		if len(r.OnchainAddress) <= 0 && len(r.PubKey) <= 0 {
			return fmt.Errorf("missing receiver destination")
		}
		if r.Amount == 0 {
			return fmt.Errorf("missing receiver amount")
		}
	}
	return nil
}

type Receiver struct {
	Amount         uint64
	OnchainAddress string // onchain
	PubKey         string // offchain
}

func (r Receiver) IsOnchain() bool {
	return len(r.OnchainAddress) > 0
}

type TxRequests []TxRequest

func (t TxRequests) CountSpentVtxos() int {
	count := 0
	for _, request := range t {
		for _, in := range request.Inputs {
			// Notes and swept vtxos are excluded from this count.
			if !in.RequiresForfeit() {
				continue
			}
			count++
		}
	}
	return count
}

func (t TxRequests) HaveOnlyOnchainOutput() bool {
	for _, request := range t {
		for _, r := range request.Receivers {
			if !r.IsOnchain() {
				return false
			}
		}
	}
	return true
}
