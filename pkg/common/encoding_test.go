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

func TestSecretKeyEncoding(t *testing.T) {
	fixtures := struct {
		SecretKey struct {
			Valid []struct {
				Key      string `json:"key"`
				Expected string `json:"expected"`
			} `json:"valid"`
			Invalid []struct {
				Key           string `json:"key"`
				ExpectedError string `json:"expectedError"`
			} `json:"invalid"`
		} `json:"secretKey"`
	}{}
	err := json.Unmarshal(f, &fixtures)
	require.NoError(t, err)

	t.Run("valid", func(t *testing.T) {
		for _, f := range fixtures.SecretKey.Valid {
			hrp, key, err := common.DecodeSecKey(f.Key)
			require.NoError(t, err)
			require.NotEmpty(t, hrp)
			require.NotNil(t, key)

			keyHex := hex.EncodeToString(key.Serialize())
			require.Equal(t, f.Expected, keyHex)

			keyStr, err := common.EncodeSecKey(hrp, key)
			require.NoError(t, err)
			require.Equal(t, f.Key, keyStr)
		}
	})

	t.Run("invalid", func(t *testing.T) {
		for _, f := range fixtures.SecretKey.Invalid {
			hrp, key, err := common.DecodeSecKey(f.Key)
			require.EqualError(t, err, f.ExpectedError)
			require.Empty(t, hrp)
			require.Nil(t, key)
		}
	})
}

func TestPublicKeyEncoding(t *testing.T) {
	fixtures := struct {
		PublicKey struct {
			Valid []struct {
				Key      string `json:"key"`
				Expected string `json:"expected"`
			} `json:"valid"`
			Invalid []struct {
				Key           string `json:"key"`
				ExpectedError string `json:"expectedError"`
			} `json:"invalid"`
		} `json:"publicKey"`
	}{}
	err := json.Unmarshal(f, &fixtures)
	require.NoError(t, err)

	t.Run("valid", func(t *testing.T) {
		for _, f := range fixtures.PublicKey.Valid {
			hrp, key, err := common.DecodePubKey(f.Key)
			require.NoError(t, err)
			require.NotEmpty(t, hrp)
			require.NotNil(t, key)

			keyHex := hex.EncodeToString(key.SerializeCompressed())
			require.Equal(t, f.Expected, keyHex)

			keyStr, err := common.EncodePubKey(hrp, key)
			require.NoError(t, err)
			require.Equal(t, f.Key, keyStr)
		}
	})

	t.Run("invalid", func(t *testing.T) {
		for _, f := range fixtures.PublicKey.Invalid {
			hrp, key, err := common.DecodePubKey(f.Key)
			require.EqualError(t, err, f.ExpectedError)
			require.Empty(t, hrp)
			require.Nil(t, key)
		}
	})
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

			userKeyStr, err := common.EncodePubKey(common.MainNet.PubKey, userKey)
			require.NoError(t, err)
			require.Equal(t, f.ExpectedUserKey, userKeyStr)

			aspKeyStr, err := common.EncodePubKey(common.MainNet.PubKey, aspKey)
			require.NoError(t, err)
			require.Equal(t, f.ExpectedAspKey, aspKeyStr)

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

func TestRelayKeyEncoding(t *testing.T) {
	fixtures := struct {
		RelayKey struct {
			Valid []struct {
				Key      string `json:"key"`
				Expected string `json:"expected"`
			} `json:"valid"`
			Invalid []struct {
				Key           string `json:"key"`
				ExpectedError string `json:"expectedError"`
			} `json:"invalid"`
		} `json:"relayKey"`
	}{}
	err := json.Unmarshal(f, &fixtures)
	require.NoError(t, err)

	t.Run("valid", func(t *testing.T) {
		for _, f := range fixtures.RelayKey.Valid {
			hrp, key, err := common.DecodeRelayKey(f.Key)
			require.NoError(t, err)
			require.NotEmpty(t, hrp)
			require.NotNil(t, key)

			keyHex := hex.EncodeToString(key.SerializeCompressed())
			require.Equal(t, f.Expected, keyHex)

			keyStr, err := common.EncodeRelayKey(hrp, key)
			require.NoError(t, err)
			require.Equal(t, f.Key, keyStr)
		}
	})

	t.Run("invalid", func(t *testing.T) {
		for _, f := range fixtures.RelayKey.Invalid {
			hrp, key, err := common.DecodeRelayKey(f.Key)
			require.EqualError(t, err, f.ExpectedError)
			require.Empty(t, hrp)
			require.Nil(t, key)
		}
	})
}

func TestUrlEncoding(t *testing.T) {
	fixtures := struct {
		Url struct {
			Valid []struct {
				Url            string   `json:"url"`
				ExpectedPubkey string   `json:"expectedPubkey"`
				ExpectedRelays []string `json:"expectedRelays"`
			} `json:"valid"`
			Invalid []struct {
				Url           string `json:"url"`
				ExpectedError string `json:"expectedError"`
			} `json:"invalid"`
		} `json:"url"`
	}{}
	err := json.Unmarshal(f, &fixtures)
	require.NoError(t, err)

	t.Run("valid", func(t *testing.T) {
		for _, f := range fixtures.Url.Valid {
			pubkey, relays, err := common.DecodeUrl(f.Url)
			require.NoError(t, err)
			require.NotEmpty(t, pubkey)
			require.NotNil(t, relays)

			require.Equal(t, f.ExpectedPubkey, pubkey)
			require.Exactly(t, relays, f.ExpectedRelays)

			url, err := common.EncodeUrl(pubkey, relays...)
			require.NoError(t, err)
			require.Equal(t, f.Url, url)
		}
	})

	t.Run("invalid", func(t *testing.T) {
		for _, f := range fixtures.Url.Invalid {
			pubkey, relays, err := common.DecodeUrl(f.Url)
			require.Error(t, err)
			require.Contains(t, err.Error(), f.ExpectedError)
			require.Empty(t, pubkey)
			require.Nil(t, relays)
		}
	})
}
