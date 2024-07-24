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

## Run the Ark Service Provider

|         | Covenant-less          | Covenant                               |
|---------|------------------------|----------------------------------------|
| Network | Bitcoin (regtest only)<br/>⚠️ *Mainnet & Testnet coming soon* | Liquid, Liquid testnet, Liquid regtest |
| Wallet  | Embedded [lnwallet](https://pkg.go.dev/github.com/lightningnetwork/lnd/lnwallet/btcwallet) in `arkd`     | [Ocean](https://github.com/vulpemventures/ocean) wallet                           |

> The covenant version of Ark requires [special tapscript opcodes](https://github.com/ElementsProject/elements/blob/master/doc/tapscript_opcodes.md) only available on Liquid Network.

### Covenant-less Ark

#### Run the daemon (regtest)

Run locally with [Docker](https://docs.docker.com/engine/install/) and [Nigiri](https://nigiri.vulpem.com/).

```
nigiri start
docker compose -f ./docker-compose.clark.regtest.yml up -d
```

the compose file will start a `clarkd` container exposing Ark API on localhost:6000.

#### Fund the embedded wallet

The ASP needs funds to operate. the `v1/admin/address` allows to generate a new address. This endpoint is protected by Basic Authorization token.

```
curl http://localhost:6000/v1/admin/address -H 'Authorization: Basic YWRtaW46YWRtaW4=' 
```

> This exemple is using the default USER/PASSWORD credentials. You can customize them by setting the `ARK_AUTH_USER` and `ARK_AUTH_PASS` variables.

Faucet the address using nigiri

```
nigiri faucet <ASP_address>
```

### Ark client

Inside the `arkd` container is shipped the `ark` CLI. You can submit payment to the ASP using the `ark` CLI.

```bash
alias ark='docker exec -it arkd ark'
ark init --password <password> --ark-url localhost:8080
```

This will add a `state.json` file to the following directory:

- POSIX (Linux/BSD): ~/.Ark-cli
- Mac OS: $HOME/Library/Application Support/Ark-cli
- Windows: %LOCALAPPDATA%\Ark-cli
- Plan 9: $home/Ark-cli

**Note:** you can use a different datadir by exporting the env var `ARK_WALLET_DATADIR` like:

```bash
export ARK_WALLET_DATADIR=path/to/custom
ark init --password <password> --ark-url localhost:8080 --network regtest
```

Add funds to the ark wallet:

```bash
ark receive
{
  "offchain_address": <address starting with "tark1q...">,
  "onchain_address": <address starting with "tex1q...">
}
```

Onboard the ark:

```bash
ark onboard --amount 21000
```

After confirmation, ark wallet will be funded and ready to spend offchain.

In **another tab**, setup another ark wallet with:

```bash
export ARK_WALLET_DATADIR=./datadir
alias ark2=$(pwd)/build/ark-<os>-<arch>
ark2 init --password <password> --ark-url localhost:8080 --network testnet
```

**Note:** `ark2` should always run in the second tab.

### Make payments

You can now make ark payments between the 2 ark wallets:

```bash
ark2 receive
{
  "offchain_address": <address starting with "tark1q...">,
  "onchain_address": <address starting with "tex1q...">,
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

#### Send async payment

```bash
ark send --to <ark_address> --async
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

