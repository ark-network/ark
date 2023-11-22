package domain

type Payment struct {
	Id        string
	Inputs    []Vtxo
	Receivers []Receiver
}

func (p Payment) TotOutputAmount() uint64 {
	tot := uint64(0)
	for _, r := range p.Receivers {
		tot += r.Amount
	}
	return tot
}

type Vtxo struct {
	Txid string
	VOut uint32
}

type Receiver struct {
	Pubkey string
	Amount uint64
}
