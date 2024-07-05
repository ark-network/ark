package covenantless

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/ark-network/ark-cli/utils"
	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/urfave/cli/v2"
	"github.com/vulpemventures/go-elements/network"
)

var explorerUrls = map[string]string{
	network.Liquid.Name:  "https://blockstream.info/liquid/api",
	network.Testnet.Name: "https://blockstream.info/liquidtestnet/api",
	network.Regtest.Name: "http://localhost:3001",
}

func (c *clArkBitcoinCLI) Init(ctx *cli.Context) error {
	key := ctx.String("prvkey")
	net := strings.ToLower(ctx.String("network"))
	url := ctx.String("ark-url")
	explorer := ctx.String("explorer")

	var explorerURL string

	if len(url) <= 0 {
		return fmt.Errorf("invalid ark url")
	}
	if net != "liquid" && net != "testnet" && net != "regtest" {
		return fmt.Errorf("invalid network")
	}

	if len(explorer) > 0 {
		explorerURL = explorer
	} else {
		explorerURL = explorerUrls[net]
	}

	if err := connectToAsp(ctx, net, url, explorerURL); err != nil {
		return err
	}

	password, err := utils.ReadPassword(ctx, false)
	if err != nil {
		return err
	}

	return initWallet(ctx, key, password)
}

func generateRandomPrivateKey() (*secp256k1.PrivateKey, error) {
	privKey, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, err
	}
	return privKey, nil
}

func connectToAsp(ctx *cli.Context, net, url, explorer string) error {
	client, close, err := getClient(url)
	if err != nil {
		return err
	}
	defer close()

	resp, err := client.GetInfo(ctx.Context, &arkv1.GetInfoRequest{})
	if err != nil {
		return err
	}

	return utils.SetState(ctx, map[string]string{
		utils.ASP_URL:               url,
		utils.NETWORK:               net,
		utils.ASP_PUBKEY:            resp.Pubkey,
		utils.ROUND_LIFETIME:        strconv.Itoa(int(resp.GetRoundLifetime())),
		utils.UNILATERAL_EXIT_DELAY: strconv.Itoa(int(resp.GetUnilateralExitDelay())),
		utils.EXPLORER:              explorer,
	})
}

func initWallet(ctx *cli.Context, key string, password []byte) error {
	var privateKey *secp256k1.PrivateKey
	if len(key) <= 0 {
		privKey, err := generateRandomPrivateKey()
		if err != nil {
			return err
		}
		privateKey = privKey
	} else {
		privKeyBytes, err := hex.DecodeString(key)
		if err != nil {
			return err
		}

		privateKey = secp256k1.PrivKeyFromBytes(privKeyBytes)
	}

	cypher := utils.NewAES128Cypher()
	buf := privateKey.Serialize()
	encryptedPrivateKey, err := cypher.Encrypt(buf, password)
	if err != nil {
		return err
	}

	passwordHash := utils.HashPassword([]byte(password))

	pubkey := privateKey.PubKey().SerializeCompressed()
	state := map[string]string{
		utils.ENCRYPTED_PRVKEY: hex.EncodeToString(encryptedPrivateKey),
		utils.PASSWORD_HASH:    hex.EncodeToString(passwordHash),
		utils.PUBKEY:           hex.EncodeToString(pubkey),
	}

	if err := utils.SetState(ctx, state); err != nil {
		return err
	}

	fmt.Println("wallet initialized")
	return nil
}
