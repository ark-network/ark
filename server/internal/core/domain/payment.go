package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/google/uuid"
)

type SigningType uint8

const (
	SignAll SigningType = iota
	SignBranch
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

type VtxoKey struct {
	Txid string
	VOut uint32
}

func (k VtxoKey) String() string {
	return fmt.Sprintf("%s:%d", k.Txid, k.VOut)
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
	Amount         uint64
	OnchainAddress string // onchain
	PubKey         string // offchain
}

func (r Receiver) IsOnchain() bool {
	return len(r.OnchainAddress) > 0
}

type Vtxo struct {
	VtxoKey
	Amount    uint64
	PubKey    string
	RoundTxid string
	SpentBy   string // round txid or redeem txid
	Spent     bool
	Redeemed  bool
	Swept     bool
	ExpireAt  int64
	RedeemTx  string // empty if in-round vtxo
	CreatedAt int64
}

func (v Vtxo) TapKey() (*secp256k1.PublicKey, error) {
	pubkeyBytes, err := hex.DecodeString(v.PubKey)
	if err != nil {
		return nil, err
	}
	return schnorr.ParsePubKey(pubkeyBytes)
}
