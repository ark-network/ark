package common

import (
	"fmt"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/txscript"
)

const (
	SEQUENCE_LOCKTIME_MASK         = 0x0000ffff
	SEQUENCE_LOCKTIME_TYPE_FLAG    = 1 << 22
	SEQUENCE_LOCKTIME_GRANULARITY  = 9
	SECONDS_MOD                    = 1 << SEQUENCE_LOCKTIME_GRANULARITY
	SECONDS_MAX                    = SEQUENCE_LOCKTIME_MASK << SEQUENCE_LOCKTIME_GRANULARITY
	SEQUENCE_LOCKTIME_DISABLE_FLAG = 1 << 31
)

func closerToModulo512(x uint) uint {
	return x - (x % 512)
}

func BIP68Sequence(locktime uint) (uint32, error) {
	isSeconds := locktime >= 512
	if isSeconds {
		locktime = closerToModulo512(locktime)
		if locktime > SECONDS_MAX {
			return 0, fmt.Errorf("seconds too large, max is %d", SECONDS_MAX)
		}
		if locktime%SECONDS_MOD != 0 {
			return 0, fmt.Errorf("seconds must be a multiple of %d", SECONDS_MOD)
		}
	}

	return blockchain.LockTimeToSequence(isSeconds, uint32(locktime)), nil
}

func BIP68DecodeSequence(sequence []byte) (uint, error) {
	scriptNumber, err := txscript.MakeScriptNum(sequence, true, len(sequence))
	if err != nil {
		return 0, err
	}

	if scriptNumber >= txscript.OP_1 && scriptNumber <= txscript.OP_16 {
		scriptNumber = scriptNumber - (txscript.OP_1 - 1)
	}

	asNumber := int64(scriptNumber)

	if asNumber&SEQUENCE_LOCKTIME_DISABLE_FLAG != 0 {
		return 0, fmt.Errorf("sequence is disabled")
	}
	if asNumber&SEQUENCE_LOCKTIME_TYPE_FLAG != 0 {
		seconds := asNumber & SEQUENCE_LOCKTIME_MASK << SEQUENCE_LOCKTIME_GRANULARITY
		return uint(seconds), nil
	}

	return uint(asNumber), nil
}
