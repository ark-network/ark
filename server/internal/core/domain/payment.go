package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"

	"github.com/google/uuid"
)

const dustAmount = 450

type Payment struct {
	Id                    string
	Inputs                []Vtxo
	ReverseBoardingInputs []ReverseBoardingInput
	Receivers             []Receiver
}

func NewPayment(inputs []Vtxo, reverseBoardings []ReverseBoardingInput) (*Payment, error) {
	p := &Payment{
		Id:                    uuid.New().String(),
		Inputs:                inputs,
		ReverseBoardingInputs: reverseBoardings,
	}
	if err := p.validate(true); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *Payment) AddReceivers(receivers []Receiver) (err error) {
	if p.Receivers == nil {
		p.Receivers = make([]Receiver, 0)
	}
	p.Receivers = append(p.Receivers, receivers...)
	defer func() {
		if err != nil {
			p.Receivers = p.Receivers[:len(p.Receivers)-len(receivers)]
		}
	}()
	err = p.validate(false)
	return
}

func (p Payment) TotalInputAmount() uint64 {
	tot := uint64(0)
	for _, in := range p.Inputs {
		tot += in.Amount
	}
	for _, in := range p.ReverseBoardingInputs {
		tot += uint64(in.Value)
	}
	return tot
}

func (p Payment) TotalOutputAmount() uint64 {
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
	if len(p.Inputs) <= 0 && len(p.ReverseBoardingInputs) <= 0 {
		return fmt.Errorf("missing inputs")
	}
	if ignoreOuts {
		return nil
	}
	if len(p.Receivers) <= 0 {
		return fmt.Errorf("missing outputs")
	}
	// Check that input and output and output amounts match.
	inAmount := p.TotalInputAmount()
	outAmount := uint64(0)
	for _, r := range p.Receivers {
		if len(r.OnchainAddress) <= 0 && len(r.Pubkey) <= 0 {
			return fmt.Errorf("missing receiver destination")
		}
		if r.Amount < dustAmount {
			return fmt.Errorf("receiver amount must be greater than dust")
		}
		outAmount += r.Amount
	}
	if inAmount != outAmount {
		return fmt.Errorf("input and output amounts mismatch")
	}
	return nil
}

type VtxoKey struct {
	Txid string
	VOut uint32
}

func (k VtxoKey) Hash() string {
	calcHash := func(buf []byte, hasher hash.Hash) []byte {
		_, _ = hasher.Write(buf)
		return hasher.Sum(nil)
	}

	hash160 := func(buf []byte) []byte {
		return calcHash(calcHash(buf, sha256.New()), sha256.New())
	}

	buf, _ := hex.DecodeString(k.Txid)
	buf = append(buf, byte(k.VOut))
	return hex.EncodeToString(hash160(buf))
}

type Receiver struct {
	Pubkey         string
	Amount         uint64
	OnchainAddress string
}

func (r Receiver) IsOnchain() bool {
	return len(r.OnchainAddress) > 0
}

type Vtxo struct {
	VtxoKey
	Receiver
	PoolTx       string
	SpentBy      string // round txid or async redeem txid
	Spent        bool
	Redeemed     bool
	Swept        bool
	ExpireAt     int64
	AsyncPayment *AsyncPaymentTxs // nil if not async vtxo
}

type AsyncPaymentTxs struct {
	RedeemTx                string // always signed by the ASP when created
	UnconditionalForfeitTxs []string
}

type ReverseBoardingInput struct {
	VtxoKey
	Value          int64
	OwnerPublicKey string
}
