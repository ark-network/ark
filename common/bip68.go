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

	SECONDS_PER_BLOCK = 10 * 60 // 10 minutes
)

type LocktimeType uint

const (
	LocktimeTypeSecond LocktimeType = iota
	LocktimeTypeBlock
)

// Locktime represents a BIP68 relative timelock value.
// This struct is comparable and can be used as a map key.
type Locktime struct {
	Type  LocktimeType
	Value uint32
}

func (l Locktime) Seconds() int64 {
	if l.Type == LocktimeTypeBlock {
		return int64(l.Value) * SECONDS_PER_BLOCK
	}
	return int64(l.Value)
}

func (l Locktime) Compare(other Locktime) int {
	val := l.Seconds()
	otherVal := other.Seconds()

	if val == otherVal {
		return 0
	}
	if val < otherVal {
		return -1
	}
	return 1
}

// LessThan returns true if this locktime is less than the other locktime
func (l Locktime) LessThan(other Locktime) bool {
	return l.Compare(other) < 0
}

func BIP68Sequence(locktime Locktime) (uint32, error) {
	value := locktime.Value
	isSeconds := locktime.Type == LocktimeTypeSecond
	if isSeconds {
		if value > SECONDS_MAX {
			return 0, fmt.Errorf("seconds too large, max is %d", SECONDS_MAX)
		}
		if value%SECONDS_MOD != 0 {
			return 0, fmt.Errorf("seconds must be a multiple of %d", SECONDS_MOD)
		}
	}

	return blockchain.LockTimeToSequence(isSeconds, value), nil
}

func BIP68DecodeSequence(sequence []byte) (*Locktime, error) {
	scriptNumber, err := txscript.MakeScriptNum(sequence, true, len(sequence))
	if err != nil {
		return nil, err
	}

	if scriptNumber >= txscript.OP_1 && scriptNumber <= txscript.OP_16 {
		scriptNumber = scriptNumber - (txscript.OP_1 - 1)
	}

	asNumber := int64(scriptNumber)

	if asNumber&SEQUENCE_LOCKTIME_DISABLE_FLAG != 0 {
		return nil, fmt.Errorf("sequence is disabled")
	}
	if asNumber&SEQUENCE_LOCKTIME_TYPE_FLAG != 0 {
		seconds := asNumber & SEQUENCE_LOCKTIME_MASK << SEQUENCE_LOCKTIME_GRANULARITY
		return &Locktime{Type: LocktimeTypeSecond, Value: uint32(seconds)}, nil
	}

	return &Locktime{Type: LocktimeTypeBlock, Value: uint32(asNumber)}, nil
}
