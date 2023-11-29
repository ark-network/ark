package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"

	"github.com/google/uuid"
	"golang.org/x/crypto/ripemd160"
)

type Payment struct {
	Id        string
	Inputs    []Vtxo
	Receivers []Receiver
}

func NewPayment(inputs []Vtxo) (*Payment, error) {
	p := &Payment{
		Id:     uuid.New().String(),
		Inputs: inputs,
	}
	if err := p.validate(true); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *Payment) AddReceivers(recievers []Receiver) (err error) {
	if p.Receivers == nil {
		p.Receivers = make([]Receiver, 0)
	}
	p.Receivers = append(p.Receivers, recievers...)
	defer func() {
		if err != nil {
			p.Receivers = p.Receivers[:len(p.Receivers)-len(recievers)]
		}
	}()
	err = p.validate(false)
	return
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
	if ignoreOuts {
		return nil
	}
	if len(p.Receivers) <= 0 {
		return fmt.Errorf("missing outputs")
	}
	// Check that input and output and output amounts match.
	inAmount := uint64(0)
	for _, in := range p.Inputs {
		inAmount += in.Amount
	}
	outAmount := uint64(0)
	for _, v := range p.Receivers {
		outAmount += v.Amount
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
		return calcHash(calcHash(buf, sha256.New()), ripemd160.New())
	}

	buf, _ := hex.DecodeString(k.Txid)
	buf = append(buf, byte(k.VOut))
	return hex.EncodeToString(hash160(buf))
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
