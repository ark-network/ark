package covenant

import (
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/ark/client/utils"
	"github.com/ark-network/ark/common"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/urfave/cli/v2"
	"github.com/vulpemventures/go-elements/network"
)

var explorerUrls = map[string]string{
	common.Liquid.Name:        "https://blockstream.info/liquid/api",
	common.LiquidTestNet.Name: "https://blockstream.info/liquidtestnet/api",
	common.LiquidRegTest.Name: "http://localhost:3001",
}

func (c *covenantLiquidCLI) Init(ctx *cli.Context) error {
	key := ctx.String("prvkey")
	net := strings.ToLower(ctx.String("network"))
	url := ctx.String("asp-url")
	explorer := ctx.String("explorer")

	var explorerURL string

	if len(url) <= 0 {
		return fmt.Errorf("invalid asp-url")
	}
	if net != common.Liquid.Name && net != common.LiquidTestNet.Name && net != common.LiquidRegTest.Name {
		return fmt.Errorf("invalid network")
	}

	if len(explorer) > 0 {
		explorerURL = explorer
		if err := testEsploraEndpoint(toElementsNetworkFromName(net), explorerURL); err != nil {
			return fmt.Errorf("failed to connect with explorer: %s", err)
		}
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

func testEsploraEndpoint(net network.Network, url string) error {
	endpoint := fmt.Sprintf("%s/asset/%s", url, net.AssetID)
	resp, err := http.Get(endpoint)
	if err != nil {
		return fmt.Errorf("failed to connect with explorer: (%s) %s", endpoint, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf(endpoint + " " + string(body))
	}

	return nil
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
		utils.ONBOARDING_EXIT_DELAY: strconv.Itoa(int(resp.GetReverseBoardingExitDelay())),
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
