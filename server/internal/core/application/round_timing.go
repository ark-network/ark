package application

import "time"

type roundTiming struct {
	roundEnd time.Time
}

func newRoundTiming(roundInterval time.Duration) roundTiming {
	roundEndTime := time.Now().Add(roundInterval)
	return roundTiming{roundEndTime}
}

func (r roundTiming) remainingDuration() time.Duration {
	return time.Until(r.roundEnd)
}

// 1/6 of the remaining duration, at least 1 second
func (r roundTiming) waitForRegistration() {
	sleepingTime := r.remainingDuration() / 6
	if sleepingTime.Seconds() < 1 {
		sleepingTime = time.Second
	}
	time.Sleep(sleepingTime)
}

// the total duration of the confirmation phase if all attempts are done
func (r roundTiming) confirmationDuration() time.Duration {
	halfOfRemainingDuration := r.remainingDuration() / 2 // 50% of the remaining duration
	return halfOfRemainingDuration
}

// 33% of the remaining duration
// 1/3 for nonces collection
// 1/3 for tree signatures
// 1/3 for finalization
func (r roundTiming) finalizationPhaseDuration() time.Duration {
	return r.remainingDuration() / 3
}
