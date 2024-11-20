package domain

type MarketHour struct {
	StartTime     int64
	EndTime       int64
	Period        int64
	RoundInterval int64
	UpdatedAt     int64
}

func NewMarketHour(startTime, endTime, period, roundInterval int64) *MarketHour {
	return &MarketHour{
		StartTime:     startTime,
		EndTime:       endTime,
		Period:        period,
		RoundInterval: roundInterval,
	}
}
