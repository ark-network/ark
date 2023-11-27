---
sidebar_position: 2
title: Noah CLI
---

The Noah CLI allows you to interact with the Ark Service Provider (ASP). It is a command line tool that can be used to create and manage your Ark Wallet.

## Configure the CLI

The noah CLI requires a set of variables to be set, use flags to set them.

```bash
noah config connect <ARK_URL>
```

## Set up Noah wallet

`noah init` is a command that sets up a Noah wallet with a 32-bytes private key and a password in order to encrypt the private key.

```bash
noah init --password <PASSWORD> [--prvkey <PRIVATE_KEY>]
```

## Receive VTXO

### Get receiving address

You can use the noah CLI to print your Ark address. This can be used to receive VTXO.

```bash
noah receive
```

:::tip
testnet only: `noah faucet <AMOUNT>` to receive newly created VTXO from the service provider.
:::

### Print balance

```bash
noah balance
```

`balance` returns the sum of all VTXOs belonging to the Noah wallet.

## Send VTXO(s)

```bash
noah send --receivers '[{"to": "<ARK_ADDRESS", "amount": <AMOUNT>}, ...]'
```

Noah CLI is responsible to select the coins to send for the given amount. It will sync with the service provider to forfeit the VTXO(s) and create a new VTXO belonging to the recipient. A change VTXO will be created if needed. Asks user password before signing.

## Redemption

### Collaborative redemption

```bash
noah redeem --address <ONCHAIN_ADDRESS> --amount <AMOUNT>
```

Noah CLI will sync with the service provider in order to redeem onchain the given amount in the next round, any remaining change will become a new vTXO. Asks user password before signing.

### Unilateral redemption

```bash
noah redeem --address <ONCHAIN_ADDRESS> --force
```

With the `--force` flag Noah CLI will unilateraly redeem all VTXOs by signing the psbt(s) and broadcast them. Asks user password before signing.
