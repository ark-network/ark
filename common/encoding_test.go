package common_test

import (
	"encoding/hex"
	"encoding/json"
	"log"
	"os"
	"testing"

	common "github.com/ark-network/ark/common"
	"github.com/stretchr/testify/require"
)

var f []byte

func init() {
	var err error
	f, err = os.ReadFile("fixtures/encoding.json")
	if err != nil {
		log.Fatal(err)
	}
}

func TestAddressEncoding(t *testing.T) {
	fixtures := struct {
		Address struct {
			Valid []struct {
				Addr            string `json:"addr"`
				ExpectedUserKey string `json:"expectedUserKey"`
				ExpectedAspKey  string `json:"expectedAspKey"`
			} `json:"valid"`
			Invalid []struct {
				Addr          string `json:"addr"`
				ExpectedError string `json:"expectedError"`
			} `json:"invalid"`
		} `json:"address"`
	}{}
	err := json.Unmarshal(f, &fixtures)
	require.NoError(t, err)

	t.Run("valid", func(t *testing.T) {
		for _, f := range fixtures.Address.Valid {
			hrp, userKey, aspKey, err := common.DecodeAddress(f.Addr)
			require.NoError(t, err)
			require.NotEmpty(t, hrp)
			require.NotNil(t, userKey)
			require.NotNil(t, aspKey)

			require.NoError(t, err)
			require.Equal(t, f.ExpectedUserKey, hex.EncodeToString(userKey.SerializeCompressed()))

			require.NoError(t, err)
			require.Equal(t, f.ExpectedAspKey, hex.EncodeToString(aspKey.SerializeCompressed()))

			addr, err := common.EncodeAddress(hrp, userKey, aspKey)
			require.NoError(t, err)
			require.Equal(t, f.Addr, addr)
		}
	})

	t.Run("invalid", func(t *testing.T) {
		for _, f := range fixtures.Address.Invalid {
			hrp, userKey, aspKey, err := common.DecodeAddress(f.Addr)
			require.EqualError(t, err, f.ExpectedError)
			require.Empty(t, hrp)
			require.Nil(t, userKey)
			require.Nil(t, aspKey)
		}
	})
}
