package application

import (
	"encoding/hex"
)

type output struct {
	script []byte
	amount uint64
}

func (o output) GetScript() string {
	return hex.EncodeToString(o.script)
}
func (o output) GetAmount() uint64 {
	return o.amount
}
