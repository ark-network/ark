package application

import "fmt"

type errPaymentNotFound struct {
	id string
}

func (e errPaymentNotFound) Error() string {
	return fmt.Sprintf("payment %s not found", e.id)
}
