package flags

import (
	"github.com/ark-network/ark/common"
	"github.com/urfave/cli/v2"
)

const DATADIR_ENVVAR = "ARK_WALLET_DATADIR"

var (
	DatadirFlag = &cli.StringFlag{
		Name:     "datadir",
		Usage:    "Specify the data directory",
		Required: false,
		Value:    common.AppDataDir("ark-cli", false),
		EnvVars:  []string{DATADIR_ENVVAR},
	}
	PasswordFlag = cli.StringFlag{
		Name:     "password",
		Usage:    "password to unlock the wallet",
		Required: false,
		Hidden:   true,
	}
	AmountOnboardFlag = cli.Uint64Flag{
		Name:  "amount",
		Usage: "amount to onboard in sats",
	}
	ExpiryDetailsFlag = cli.BoolFlag{
		Name:     "compute-expiry-details",
		Usage:    "compute client-side the VTXOs expiry time",
		Value:    false,
		Required: false,
	}
	PrivateKeyFlag = cli.StringFlag{
		Name:  "prvkey",
		Usage: "optional, private key to encrypt",
	}
	NetworkFlag = cli.StringFlag{
		Name:  "network",
		Usage: "network to use (liquid, testnet, regtest, signet)",
		Value: "liquid",
	}
	UrlFlag = cli.StringFlag{
		Name:     "asp-url",
		Usage:    "the url of the ASP to connect to",
		Required: true,
	}
	ExplorerFlag = cli.StringFlag{
		Name:  "explorer",
		Usage: "the url of the explorer to use",
	}
	ReceiversFlag = cli.StringFlag{
		Name:  "receivers",
		Usage: "receivers of the send transaction, JSON encoded: '[{\"to\": \"<...>\", \"amount\": <...>}, ...]'",
	}
	ToFlag = cli.StringFlag{
		Name:  "to",
		Usage: "address of the recipient",
	}
	AmountFlag = cli.Uint64Flag{
		Name:  "amount",
		Usage: "amount to send in sats",
	}
	EnableExpiryCoinselectFlag = cli.BoolFlag{
		Name:  "enable-expiry-coinselect",
		Usage: "select vtxos that are about to expire first",
		Value: false,
	}
	AddressFlag = cli.StringFlag{
		Name:     "address",
		Usage:    "main chain address receiving the redeeemed VTXO",
		Value:    "",
		Required: false,
	}
	AmountToRedeemFlag = cli.Uint64Flag{
		Name:     "amount",
		Usage:    "amount to redeem",
		Value:    0,
		Required: false,
	}
	ForceFlag = cli.BoolFlag{
		Name:     "force",
		Usage:    "force redemption without collaborate with the Ark service provider",
		Value:    false,
		Required: false,
	}
	AsyncPaymentFlag = cli.BoolFlag{
		Name:     "async",
		Usage:    "use async payment protocol",
		Value:    false,
		Required: false,
	}
	ReverseOnboardingFlag = cli.BoolFlag{
		Name:     "reverse",
		Usage:    "reverse onboarding protocol",
		Value:    false,
		Required: false,
	}
)
