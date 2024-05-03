# Ark

![noah desiging the ark to scale Bitcoin](https://github.com/ark-network/ark/assets/3596602/5f51dde8-33d3-404f-bacf-6975131c9509)

Welcome to the Ark monorepo.

In this repository you can find:

- [`server`](./server/) always-on daemon that serves as the Ark Service Provider (ASP)
- [`client`](./client/) single-key wallet as command-line interface (CLI) to interact with the ASP

Refer to the README in each directory for more information about development.

## Roadmap

- [ ] Progressive Web App (PWA) as client and Ark wallet.
- [ ] Support Bitcoin with pre-signed transactions
- [ ] Support Ark out-of-round payments
- [ ] Add protected admin RPCs for `arkd` to manage rounds and treasury
- [ ] Add `postgres` as database option for `arkd`

## Build and Run with Docker

Run locally with Docker on Liquid Testnet. It uses `docker-compose` to build the `arkd` docker image from `server` and run the it as container, together with the `oceand` container.

### Prerequisites

- [Go](https://go.dev/doc/install)
- [Docker](https://docs.docker.com/engine/install/)

### Setup the Ocean wallet

Start `oceand` in Liquid Testnet:

```bash
docker compose up -d oceand
```

Setup `oceand`:

```bash
alias ocean='docker exec oceand ocean'
ocean config init --no-tls
ocean wallet create --password <password>
ocean wallet unlock --password <password>
```

### Run arkd connected to Ocean

Build from source `./server` and start the ASP:

```bash
docker compose up -d arkd
```

**Note:** On startup `arkd` will create an account `ark` on oceand.

Get an address from Ocean to add funds to the ASP:

```bash
ocean account derive --account-name ark
```

Fund the resulting address with [Liquid testnet faucet](https://liquidtestnet.com/faucet).

### Ark client

Inside the `arkd` container is shipped the `ark` CLI. You can submit payment to the ASP using the `ark` CLI.

```bash
alias ark='docker exec -it arkd ark'
ark init --password <password> --ark-url localhost:6000
```

This will add a `state.json` file to the following directory:

- POSIX (Linux/BSD): ~/.Ark-cli
- Mac OS: $HOME/Library/Application Support/Ark-cli
- Windows: %LOCALAPPDATA%\Ark-cli
- Plan 9: $home/Ark-cli

**Note:** you can use a different datadir by exporting the env var `ARK_WALLET_DATADIR` like:

```bash
export ARK_WALLET_DATADIR=path/to/custom
ark init --password <password> --ark-url localhost:6000 --network testnet
```

Add funds to the ark wallet:

```bash
ark receive
{
  "offchain_address": <address starting with "tark1q...">,
  "onchain_address": <address starting with "tex1q...">
}
```

Fund the `onchain_address` with https://liquidtestnet.com/faucet.

Onboard the ark:

```bash
ark onboard --amount 21000
```

After confirmation, ark wallet will be funded and ready to spend offchain.

In **another tab**, setup another ark wallet with:

```bash
export ARK_WALLET_DATADIR=./datadir
alias ark2=$(pwd)/build/ark-<os>-<arch>
ark2 init --password <password> --ark-url localhost:6000
```

**Note:** `ark2` should always run in the second tab.

### Make payments

You can now make ark payments between the 2 ark wallets:

```bash
ark2 receive
{
  "offchain_address": <address starting with "tark1q...">,
  "onchain_address": <address starting with "tex1q...">,
  "relays": ["localhost:6000"]
}
```

```bash
ark send --to <ark2 offchain address> --amount 2100
```

Both balances should reflect the payment:

```bash
ark balance
{
  "offchain_balance": 18900,
  "onchain_balance": 0
}
```

```bash
  ark2 balance
{
  "offchain_balance": 2100,
  "onchain_balance": 0
}
```

### Exiting

User `ark` can leave the ark collaboratively (i.e. ASP needs to collaborate):

```bash
ark redeem --address <onchain_address> --amount 12100
```

In the case of the ASP is not responding, you can leave the ark unilaterally (`--amount` is not necessary since `--force` will redeem all funds):

```bash
ark redeem --force
```

### Help

You can see all available commands with `help`:

```bash
ark help
```

