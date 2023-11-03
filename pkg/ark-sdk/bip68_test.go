package sdk_test

import (
	"encoding/json"
	"io/ioutil"
	"testing"

	sdk "github.com/ark-network/ark-sdk"
)

func TestBIP68(t *testing.T) {
	// Load the fixture data from bip68.json
	data, err := ioutil.ReadFile("fixtures/bip68.json")
	if err != nil {
		t.Fatalf("failed to read fixture data: %v", err)
	}

	// Parse the fixture data into a slice of test cases
	var testCases []struct {
		Input    int    `json:"seconds"`
		Expected int64  `json:"sequence"`
		Desc     string `json:"description"`
	}
	if err := json.Unmarshal(data, &testCases); err != nil {
		t.Fatalf("failed to parse fixture data: %v", err)
	}

	if len(testCases) == 0 {
		t.Fatalf("no test cases found")
	}

	// Run each test case
	for _, tc := range testCases {
		t.Run(tc.Desc, func(t *testing.T) {
			// Call the BIP68 function with the input from the test case
			actual, err := sdk.BIP68(tc.Input)
			if err != nil {
				t.Fatalf("BIP68(%d) failed: %v", tc.Input, err)
			}

			// bytes to int64
			var asNumber int64
			for i := len(actual) - 1; i >= 0; i-- {
				asNumber = asNumber<<8 | int64(actual[i])
			}

			// Compare the actual result to the expected result from the test case
			if asNumber != tc.Expected {
				t.Errorf("BIP68(%d) = %v, expected %v", tc.Input, actual, tc.Expected)
			} else {
				t.Logf("BIP68(%d) = %v", tc.Input, actual)
			}
		})
	}
}
