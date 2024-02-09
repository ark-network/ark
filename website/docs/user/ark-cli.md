---
sidebar_position: 2
title: Ark CLI
---

The Ark CLI allows you to interact with the Ark Service Provider (ASP). It is a command line tool that can be used to create and manage your Ark Wallet.

## Configure the CLI

The CLI requires an initial setup to initialize the wallet and connect to the ASP:

```bash
$ ark init init --password <PASSWORD> --ark-url <ARK_URL>
```

You can also restore a wallet by specifying the hex encoded private key with the `--prvkey` flag.

## Receive VTXO

### Get receiving address

You can print your onchain and offchain receiving addresses to receive funds with:

```bash
$ ark receive
```

This command also shows the list of relays used to reach the ASP.

:::tip
testnet only: `ark faucet` to receive newly created VTXO from the service provider.
:::

### Print balance

You can see both the onchain and offchain balance of the wallet with:
```bash
$ ark balance
```

## Send VTXO(s)

You can make an offchain payment by sending to either one or many receivers:

```bash
$ ark send --to <ARK_ADDRESS> --amount <AMOUNT>
$ ark send --receivers '[{"to": "<ARK_ADDRESS>", "amount": <AMOUNT>}, ...]'
```

The amount must be specified in _sats_ unit.

## Redemption

### Collaborative redemption

You can redeem onchain your funds by collaborating with the ASP with:

```bash
$ ark redeem --address <ONCHAIN_ADDRESS> --amount <AMOUNT>
```

Any change produced with this operation goes to your offchain address.

### Unilateral redemption

If the ASP is unresponsive you can redeem all your offchain funds unilaterally with:

```bash
$ ark redeem --address <ONCHAIN_ADDRESS> --force
```

