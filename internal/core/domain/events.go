package domain

type RoundEvent interface {
	isEvent()
}

func (r PaymentRegistrationStarted) isEvent() {}
func (r PaymentRegistrationEnded) isEvent()   {}
func (r PaymentFinalizationStarted) isEvent() {}
func (r PaymentFinalizationEnded) isEvent()   {}
func (r RoundFailed) isEvent()                {}
func (r InputsRegistered) isEvent()           {}
func (r OutputsRegistered) isEvent()          {}

type PaymentRegistrationStarted struct {
	Id        string
	Timestamp int64
}

type PaymentRegistrationEnded struct {
	Id             string
	ForfeitTxs     []string
	CongestionTree []string
}

type PaymentFinalizationStarted struct {
	Id string
}

type PaymentFinalizationEnded struct {
	Id   string
	Txid string
}

type RoundFailed struct {
	Id  string
	Err error
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
