package bip322

import "fmt"

var (
	ErrMissingInputs             = fmt.Errorf("missing inputs")
	ErrMissingData               = fmt.Errorf("missing data")
	ErrMissingWitnessUtxo        = fmt.Errorf("missing witness utxo")
	ErrInvalidSighashType        = fmt.Errorf("invalid sighash type, expected SIGHASH_ALL")
	ErrIncompletePSBT            = fmt.Errorf("incomplete psbt, missing signatures on inputs")
	ErrInvalidTxNumberOfInputs   = fmt.Errorf("invalid tx, expected at least 2 inputs")
	ErrInvalidTxNumberOfOutputs  = fmt.Errorf("invalid tx, expected 1 output")
	ErrInvalidTxWrongTxHash      = fmt.Errorf("invalid tx, wrong tx hash in first input")
	ErrInvalidTxWrongOutputIndex = fmt.Errorf("invalid tx, wrong output index in first input")
	ErrInvalidTxWrongOutput      = fmt.Errorf("invalid tx, wrong output, expected OP_RETURN with O value")
	ErrPrevoutNotFound           = fmt.Errorf("prevout not found")
)
