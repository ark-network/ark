---
sidebar_position: 2
title: 'Ark (Liquid)'
---

:::info
🚧 This page is currently under development, and some concepts may not be entirely accurate. We greatly value your feedback and contributions. If you have any suggestions, corrections, or would like to submit edits, please do so through the pull request link available at the bottom of each page.
:::

## Overview

Ark is a Go implementation of Ark that uses covenants (on the Liquid network).

This is a Proof of Concept in a very early phase of development.

## Requirements

- [Go](https://go.dev/doc/install)
- [Ocean](https://github.com/vulpemventures/ocean)

## Demo

### Start ocean wallet

Clone ocean repo:

```
$ git clone https://github.com/vulpemventures/ocean
$ cd ocean
```

Change `run` target on Makefile with:

```
run: clean
	@echo "Running oceand..."
	@export OCEAN_NETWORK=testnet; \
	export OCEAN_LOG_LEVEL=5; \
	export OCEAN_DB_TYPE=badger; \
	export OCEAN_NO_TLS=true; \
	export OCEAN_STATS_INTERVAL=120; \
	export OCEAN_ELECTRUM_URL=ssl://blockstream.info:465; \
	export OCEAN_UTXO_EXPIRY_DURATION_IN_SECONDS=60; \
	go run ./cmd/oceand
```

Start ocean:

```
$ make run
```

Setup the wallet:

```
$ make build-cli
$ alias ocean-cli=$(pwd)/build/ocean-cli-<os>-<arch>
$ ocean-cli config init --no-tls
$ ocean-cli wallet create --password password
$ ocean-cli wallet unlock --password password
$ ocean-cli account create --label ark --unconf
$ ocean-cli account derive --account-name ark
```

### Fund wallet

Fund the address with https://liquidtestnet.com/faucet.

### Start Ark Service Provider

Clone ark repo:

```
$ git clone https://github.com/ark-network/ark
$ cd ark
```

Start the ASP:

```
$ cd asp
$ make run
```

### Setup noah wallet

Setup noah wallet with:

```
$ cd noah
$ make build
$ alias noah1=$(pwd)/build/noah-<os>-<arch>
$ noah1 init --password password --ark-url localhost:6000
$ noah1 faucet
# noah1 now has 10000 sats on ark
```

In **another tab**, setup another noah wallet with:

```
$ export NOAH_DATADIR=./datadir
$ alias noah2=$(pwd)/build/noah-<os>-<arch>
$ noah2 init --password password --ark-url localhost:6000
$ noah2 faucet
# noah2 now has 10000 sats on ark
```

Note: `noah2` should always run in the second tab.

### Make payments

You can now try making ark payments between the 2 noah wallets:

```
$ noah1 receive
{
	"offchain_address": <address starting with "tark1q...">,
	"onchain_address": <address starting with "tex1q...">,
	"relays": [
		"localhost:6000"
	]
}
```

```
$ noah2 send --to <offchain_address> --amount 2100
```

Both balances should reflect the payment:

```
$ noah1 balance
{
	"offchain_balance": 12100,
	"onchain_balance": 0
}
```

```
$ noah2 balance
{
	"offchain_balance": 7900,
	"onchain_balance": 0
}
```

### Exiting

User `noah1` can leave the ark collaboratively (i.e. ASP needs to collaborate):

```
$ noah1 redeem --address <onchain_address> --amount 12100
```

In the case of the ASP is not responding, `noah1` can leave the ark unilaterally (`--amount` is not necessary since `--force` will redeem all funds):

```
$ noah1 redeem --address <onchain_address> --force
```

### Help

You can see all available commands with `help`:

```
$ noah1 help
```
