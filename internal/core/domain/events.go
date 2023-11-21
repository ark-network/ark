package domain

type RoundEvent interface {
	isEvent()
}

func (r RoundStarted) isEvent()             {}
func (r RoundFinalizationStarted) isEvent() {}
func (r RoundFinalized) isEvent()           {}
func (r RoundFailed) isEvent()              {}
func (r InputsRegistered) isEvent()         {}
func (r OutputsRegistered) isEvent()        {}

type RoundStarted struct {
	Id        string
	Timestamp int64
}

type RoundFinalizationStarted struct {
	Id             string
	ForfeitTxs     []string
	CongestionTree []string
	Connectors     []string
	PoolTx         string
}

type RoundFinalized struct {
	Id        string
	Txid      string
	Timestamp int64
}

type RoundFailed struct {
	Id        string
	Err       error
	Timestamp int64
}

type InputsRegistered struct {
	Id            string
	PaymentId     string
	PaymentInputs []Vtxo
}

type OutputsRegistered struct {
	Id             string
	PaymentId      string
	PaymentOutputs []Receiver
}
