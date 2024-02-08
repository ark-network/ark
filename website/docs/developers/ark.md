---
sidebar_position: 2
title: 'Ark (Liquid)'
---

:::info
🚧 This page is currently under development, and some concepts may not be entirely accurate. We greatly value your feedback and contributions. If you have any suggestions, corrections, or would like to submit edits, please do so through the pull request link available at the bottom of each page.
:::

## Overview

Ark is a Go implementation of Ark that uses covenants (on the Liquid network).

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

Start ocean with `make run`.

Setup the wallet:

```
$ make build-cli
$ alias ocean-cli=$(pwd)/build/ocean-cli-darwin-$(arch)
$ ocean-cli config init --no-tls
$ ocean-cli wallet create --password password
$ ocean-cli wallet unlock --password password
$ ocean-cli account create --label ark
$ ocean-cli account derive --account-name ark
```

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
$ alias noah-cli=$(pwd)/build/noah-darwin-$(arch)
$ noah-cli config connect localhost:6000 --network testnet
$ noah-cli init --password password --ark-url localhost:6000 --network testnet
$ noah-cli faucet
```

In another tab, setup another noah wallet with:

```
$ export NOAH_DATADIR=./datadir
# repeat above steps
```

You can now try making ark payments between the 2 noah wallets.
