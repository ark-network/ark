package utils

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/ark-network/ark/common"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/urfave/cli/v2"
)

const (
	ASP_URL               = "asp_url"
	ASP_PUBKEY            = "asp_public_key"
	ROUND_LIFETIME        = "round_lifetime"
	UNILATERAL_EXIT_DELAY = "unilateral_exit_delay"
	ENCRYPTED_PRVKEY      = "encrypted_private_key"
	PASSWORD_HASH         = "password_hash"
	PUBKEY                = "public_key"
	NETWORK               = "network"
	EXPLORER              = "explorer"

	defaultNetwork = "liquid"
	state_file     = "state.json"
)

var initialState = map[string]string{
	ASP_URL:               "",
	ASP_PUBKEY:            "",
	ROUND_LIFETIME:        "",
	UNILATERAL_EXIT_DELAY: "",
	ENCRYPTED_PRVKEY:      "",
	PASSWORD_HASH:         "",
	PUBKEY:                "",
	NETWORK:               defaultNetwork,
}

func GetNetwork(ctx *cli.Context) (*common.Network, error) {
	state, err := GetState(ctx)
	if err != nil {
		return nil, err
	}

	net, ok := state[NETWORK]
	if !ok {
		return nil, fmt.Errorf("network not found in state")
	}
	return networkFromString(net), nil
}

func GetRoundLifetime(ctx *cli.Context) (int64, error) {
	state, err := GetState(ctx)
	if err != nil {
		return -1, err
	}

	lifetime := state[ROUND_LIFETIME]
	if len(lifetime) <= 0 {
		return -1, fmt.Errorf("missing round lifetime")
	}

	roundLifetime, err := strconv.Atoi(lifetime)
	if err != nil {
		return -1, err
	}
	return int64(roundLifetime), nil
}

func GetUnilateralExitDelay(ctx *cli.Context) (int64, error) {
	state, err := GetState(ctx)
	if err != nil {
		return -1, err
	}

	delay := state[UNILATERAL_EXIT_DELAY]
	if len(delay) <= 0 {
		return -1, fmt.Errorf("missing unilateral exit delay")
	}

	redeemDelay, err := strconv.Atoi(delay)
	if err != nil {
		return -1, err
	}

	return int64(redeemDelay), nil
}

func GetWalletPublicKey(ctx *cli.Context) (*secp256k1.PublicKey, error) {
	state, err := GetState(ctx)
	if err != nil {
		return nil, err
	}

	publicKeyString := state[PUBKEY]
	if len(publicKeyString) <= 0 {
		return nil, fmt.Errorf("missing public key")
	}

	publicKeyBytes, err := hex.DecodeString(publicKeyString)
	if err != nil {
		return nil, err
	}

	return secp256k1.ParsePubKey(publicKeyBytes)
}

func GetAspPublicKey(ctx *cli.Context) (*secp256k1.PublicKey, error) {
	state, err := GetState(ctx)
	if err != nil {
		return nil, err
	}

	arkPubKey := state[ASP_PUBKEY]
	if len(arkPubKey) <= 0 {
		return nil, fmt.Errorf("missing asp public key")
	}

	pubKeyBytes, err := hex.DecodeString(arkPubKey)
	if err != nil {
		return nil, err
	}

	return secp256k1.ParsePubKey(pubKeyBytes)
}

func GetState(ctx *cli.Context) (map[string]string, error) {
	datadir := ctx.String("datadir")
	stateFilePath := filepath.Join(datadir, state_file)
	file, err := os.ReadFile(stateFilePath)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		if err := setInitialState(stateFilePath); err != nil {
			return nil, err
		}
		return initialState, nil
	}

	data := map[string]string{}
	if err := json.Unmarshal(file, &data); err != nil {
		return nil, err
	}

	return data, nil
}

func PrivateKeyFromPassword(ctx *cli.Context) (*secp256k1.PrivateKey, error) {
	state, err := GetState(ctx)
	if err != nil {
		return nil, err
	}

	encryptedPrivateKeyString := state[ENCRYPTED_PRVKEY]
	if len(encryptedPrivateKeyString) <= 0 {
		return nil, fmt.Errorf("missing encrypted private key")
	}

	encryptedPrivateKey, err := hex.DecodeString(encryptedPrivateKeyString)
	if err != nil {
		return nil, fmt.Errorf("invalid encrypted private key: %s", err)
	}

	password, err := ReadPassword(ctx, true)
	if err != nil {
		return nil, err
	}
	fmt.Println("wallet unlocked")

	cypher := NewAES128Cypher()
	privateKeyBytes, err := cypher.decrypt(encryptedPrivateKey, password)
	if err != nil {
		return nil, err
	}

	privateKey := secp256k1.PrivKeyFromBytes(privateKeyBytes)
	return privateKey, nil
}

func SetState(ctx *cli.Context, data map[string]string) error {
	currentData, err := GetState(ctx)
	if err != nil {
		return err
	}

	mergedData := merge(currentData, data)

	jsonString, err := json.Marshal(mergedData)
	if err != nil {
		return err
	}

	datadir := ctx.String("datadir")
	statePath := filepath.Join(datadir, state_file)

	err = os.WriteFile(statePath, jsonString, 0755)
	if err != nil {
		return fmt.Errorf("writing to file: %w", err)
	}

	return nil
}

func networkFromString(net string) *common.Network {
	switch net {
	case common.Liquid.Name:
		return &common.Liquid
	case common.LiquidTestNet.Name:
		return &common.LiquidTestNet
	case common.LiquidRegTest.Name:
		return &common.LiquidRegTest
	case common.Bitcoin.Name:
		return &common.Bitcoin
	case common.BitcoinTestNet.Name:
		return &common.BitcoinTestNet
	case common.BitcoinRegTest.Name:
		return &common.BitcoinRegTest
	default:
		panic(fmt.Sprintf("unknown network (%s)", net))
	}
}

func setInitialState(stateFilePath string) error {
	jsonString, err := json.Marshal(initialState)
	if err != nil {
		return err
	}
	return os.WriteFile(stateFilePath, jsonString, 0755)
}

func getBaseURL(ctx *cli.Context) (string, error) {
	state, err := GetState(ctx)
	if err != nil {
		return "", err
	}

	baseURL := state[EXPLORER]
	if len(baseURL) <= 0 {
		return "", fmt.Errorf("missing explorer base url")
	}

	return baseURL, nil
}

func merge(maps ...map[string]string) map[string]string {
	merge := make(map[string]string, 0)
	for _, m := range maps {
		for k, v := range m {
			merge[k] = v
		}
	}
	return merge
}
