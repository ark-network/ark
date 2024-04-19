### Overview

This is a Go implementation of Ark Service Provider that uses covenants (on the Liquid network).

This is a Proof of Concept in a early phase of development.

### Requirements

- [Go](https://go.dev/doc/install)
- [Ocean](https://github.com/vulpemventures/ocean)
- [Docker](https://docs.docker.com/engine/install/)

### Ocean wallet

Start oceand:

```
$ docker compose up -d oceand
```

Setup oceand:

```
$ alias ocean='docker exec oceand ocean'
$ ocean config init --no-tls
$ ocean wallet create --password <password>
$ ocean wallet unlock --password <password>
```

### Ark Service Provider

Start the ASP:

```
$ docker compose up -d arkd
```

**Note:** On startup `arkd` will create an account `ark` on oceand.

Add funds to the ASP:

```
$ ocean account derive --account-name ark
```

Fund the resulting address with https://liquidtestnet.com/faucet.

### Ark client

Build ark client:

```
$ cd client
$ make build
$ alias ark=$(pwd)/build/ark-<os>-<arch>
```

Initialise ark wallet:

```
$ ark init --password <password> --ark-url localhost:6000
```

This will add a `state.json` file to the following directory:

- POSIX (Linux/BSD): ~/.Ark-cli
- Mac OS: $HOME/Library/Application Support/Ark-cli
- Windows: %LOCALAPPDATA%\Ark-cli
- Plan 9: $home/Ark-cli

**Note:** you can use a different datadir by exporting the env var `ARK_WALLET_DATADIR` like:

```bash
$ export ARK_WALLET_DATADIR=path/to/custom
$ ark init --password <password> --ark-url localhost:6000
```

Add funds to the ark wallet:

```
$ ark receive
{
	"offchain_address": <address starting with "tark1q...">,
	"onchain_address": <address starting with "tex1q...">
}
```

Fund the `onchain_address` with https://liquidtestnet.com/faucet.

Onboard the ark:

```
$ ark onboard --amount 21000
```

After confirmation, ark wallet will be funded and ready to spend offchain.

In **another tab**, setup another ark wallet with:

```
$ export ARK_WALLET_DATADIR=./datadir
$ alias ark2=$(pwd)/build/ark-<os>-<arch>
$ ark2 init --password <password> --ark-url localhost:6000
```

**Note:** `ark2` should always run in the second tab.

### Make payments

You can now make ark payments between the 2 ark wallets:

```
$ ark2 receive
{
	"offchain_address": <address starting with "tark1q...">,
	"onchain_address": <address starting with "tex1q...">,
	"relays": [
		"localhost:6000"
	]
}
```

```
$ ark send --to <ark2 offchain address> --amount 2100
```

Both balances should reflect the payment:

```
$ ark balance
{
	"offchain_balance": 18900,
	"onchain_balance": 78872
}
```

```
$ ark2 balance
{
	"offchain_balance": 2100,
	"onchain_balance": 0
}
```

### Exiting

User `ark` can leave the ark collaboratively (i.e. ASP needs to collaborate):

```
$ ark redeem --address <onchain_address> --amount 12100
```

In the case of the ASP is not responding, you can leave the ark unilaterally (`--amount` is not necessary since `--force` will redeem all funds):

```
$ ark redeem --address <onchain_address> --force
```

### Help

You can see all available commands with `help`:

```
$ ark help
```
