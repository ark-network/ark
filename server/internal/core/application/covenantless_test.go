package application

import (
	"testing"
	"time"
)

func TestNextMarketHour(t *testing.T) {
	marketHourStartTime := parseTime("2023-10-10 13:00:00") //13 16 19 22 01 04
	marketHourEndTime := parseTime("2023-10-10 13:05:00")
	period := int64(3 * 3600) // 3 hours in seconds

	testCases := []struct {
		now           time.Time
		expectedStart time.Time
		expectedEnd   time.Time
		expectError   bool
		description   string
	}{
		{
			now:           parseTime("2023-10-10 13:00:00"),
			expectedStart: parseTime("2023-10-10 13:00:00"),
			expectedEnd:   parseTime("2023-10-10 13:05:00"),
			expectError:   false,
			description:   "Now is exactly at the initial market hour start time",
		},
		{
			now:           parseTime("2023-10-10 13:02:00"),
			expectedStart: parseTime("2023-10-10 16:00:00"),
			expectedEnd:   parseTime("2023-10-10 16:05:00"),
			expectError:   false,
			description:   "Now is during the market period",
		},
		{
			now:           parseTime("2023-10-10 13:05:00"),
			expectedStart: parseTime("2023-10-10 16:00:00"),
			expectedEnd:   parseTime("2023-10-10 16:05:00"),
			expectError:   false,
			description:   "Now is exactly at the market hour end time",
		},
		{
			now:           parseTime("2023-10-10 13:06:00"),
			expectedStart: parseTime("2023-10-10 16:00:00"),
			expectedEnd:   parseTime("2023-10-10 16:05:00"),
			expectError:   false,
			description:   "Now is just after the market period",
		},
		{
			now:           parseTime("2023-10-10 22:01:00"),
			expectedStart: parseTime("2023-10-11 01:00:00"),
			expectedEnd:   parseTime("2023-10-11 01:05:00"),
			expectError:   false,
			description:   "Now is much later",
		},
		{
			now:           parseTime("2023-10-10 16:01:00"),
			expectedStart: parseTime("2023-10-10 19:00:00"),
			expectedEnd:   parseTime("2023-10-10 19:05:00"),
			expectError:   false,
			description:   "Now is during a later market period",
		},
		{
			now:           parseTime("2023-10-10 15:59:00"),
			expectedStart: parseTime("2023-10-10 16:00:00"),
			expectedEnd:   parseTime("2023-10-10 16:05:00"),
			expectError:   false,
			description:   "Now is just before the next market period",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			var startTimeUnix, endTimeUnix int64
			var err error

			switch tc.description {
			case "Period is zero":
				startTimeUnix, endTimeUnix, err = calcNextMarketHour(
					marketHourStartTime.Unix(),
					marketHourEndTime.Unix(),
					0,
					tc.now.Unix(),
				)
			case "Market hour end time before start time":
				invalidEndTime := marketHourStartTime.Add(-5 * time.Minute)
				startTimeUnix, endTimeUnix, err = calcNextMarketHour(
					marketHourStartTime.Unix(),
					invalidEndTime.Unix(),
					period,
					tc.now.Unix(),
				)
			default:
				startTimeUnix, endTimeUnix, err = calcNextMarketHour(
					marketHourStartTime.Unix(),
					marketHourEndTime.Unix(),
					period,
					tc.now.Unix(),
				)
			}

			if tc.expectError {
				if err == nil {
					t.Errorf("Expected an error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Did not expect an error but got: %v", err)
				}
				expectedStartUnix := tc.expectedStart.Unix()
				expectedEndUnix := tc.expectedEnd.Unix()
				if startTimeUnix != expectedStartUnix {
					t.Errorf("Expected start time %v, got %v", tc.expectedStart.UTC(), time.Unix(startTimeUnix, 0).UTC())
				}
				if endTimeUnix != expectedEndUnix {
					t.Errorf("Expected end time %v, got %v", tc.expectedEnd.UTC(), time.Unix(endTimeUnix, 0).UTC())
				}
			}
		})
	}
}

// Helper function to parse time strings in UTC
func parseTime(value string) time.Time {
	layout := "2006-01-02 15:04:05"
	t, err := time.ParseInLocation(layout, value, time.UTC)
	if err != nil {
		panic(err)
	}
	return t
}
