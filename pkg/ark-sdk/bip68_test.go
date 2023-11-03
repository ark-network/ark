package sdk_test

import (
	"encoding/json"
	"io/ioutil"
	"testing"

	sdk "github.com/ark-network/ark-sdk"
	"github.com/stretchr/testify/require"
)

func TestBIP68(t *testing.T) {
	data, err := ioutil.ReadFile("fixtures/bip68.json")
	require.NoError(t, err)

	var testCases []struct {
		Input    int    `json:"seconds"`
		Expected int64  `json:"sequence"`
		Desc     string `json:"description"`
	}
	err = json.Unmarshal(data, &testCases)
	require.NoError(t, err)
	require.NotEmpty(t, testCases)

	for _, tc := range testCases {
		t.Run(tc.Desc, func(t *testing.T) {
			actual, err := sdk.BIP68(tc.Input)
			require.NoError(t, err)

			var asNumber int64
			for i := len(actual) - 1; i >= 0; i-- {
				asNumber = asNumber<<8 | int64(actual[i])
			}

			require.Equal(t, tc.Expected, asNumber)
		})
	}
}
