package sdk

import (
	"encoding/hex"
	"fmt"
)

const (
	SEQUENCE_LOCKTIME_MASK        = 0x0000ffff
	SEQUENCE_LOCKTIME_TYPE_FLAG   = 1 << 22
	SEQUENCE_LOCKTIME_GRANULARITY = 9
	SECONDS_MOD                   = 1 << SEQUENCE_LOCKTIME_GRANULARITY
	SECONDS_MAX                   = SEQUENCE_LOCKTIME_MASK << SEQUENCE_LOCKTIME_GRANULARITY
)

func closerToModulo512(x int) int {
	return x - (x % 512)
}

// BIP68 returns the encoded sequence locktime for the given number of seconds.
func BIP68(seconds int) ([]byte, error) {
	seconds = closerToModulo512(seconds)
	if seconds > SECONDS_MAX {
		return nil, fmt.Errorf("seconds too large, max is %d", SECONDS_MAX)
	}
	if seconds%SECONDS_MOD != 0 {
		return nil, fmt.Errorf("seconds must be a multiple of %d", SECONDS_MOD)
	}

	asNumber := SEQUENCE_LOCKTIME_TYPE_FLAG | (seconds >> SEQUENCE_LOCKTIME_GRANULARITY)
	hexString := fmt.Sprintf("%x", asNumber)
	reversed, err := hex.DecodeString(hexString)
	if err != nil {
		return nil, err
	}
	for i, j := 0, len(reversed)-1; i < j; i, j = i+1, j-1 {
		reversed[i], reversed[j] = reversed[j], reversed[i]
	}
	return reversed, nil
}
