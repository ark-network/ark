package application

import "fmt"

type errTxRequestNotFound struct {
	id string
}

func (e errTxRequestNotFound) Error() string {
	return fmt.Sprintf("tx request %s not found", e.id)
}
