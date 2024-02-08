---
sidebar_position: 3
title: 'clArk (Bitcoin)'
---

:::info
🚧 This page is currently under development, and some concepts may not be entirely accurate. We greatly value your feedback and contributions. If you have any suggestions, corrections, or would like to submit edits, please do so through the pull request link available at the bottom of each page.
:::

## Overview

Covenant Less Ark (or `clArk` for short) is a Rust implementation of Ark without using covenants (i.e. based on pre-signed transactions).

## Requirements

- [Rust](https://www.rust-lang.org/tools/install)
- [Bitcoin](https://bitcoin.org/en/download)

## Demo

Clone this [repo](https://github.com/ark-network/ark) and then change to directory `clArk`

```
$ cd clArk
```

You can play around with the tools as follows:

First you have to setup a regtest bitcoind node, there is a script provided for
that. If you want to run your own node, keep in mind that for now, we need it
to have the txindex enabled.

```
$ ./run_bitcoind.sh
```

You can interact with the node using `bitcoin-cli` as follows:

```
$ bitcoin-cli -regtest -rpcuser=user -rpcpassword=pass getnetworkinfo
```

Then, you can run an arkd server:

```
$ cargo run --bin arkd
```

This will start the server and it will work immediately. The configuration
currently is hard-coded in the `arkd/src/main.rs` file, and can only be changed
there. For arkd to work properly, you should fund it with some liquidity, this
can be done by sending some money to the address that is printed out when arkd
is started. You can send money there as follows:

```
$ bitcoin-cli -regtest -rpcuser=user -rpcpassword=pass generatetoaddress 1 <asp-addr>
# Then give it 100 confirmations because it's a coinbase output.
$ bitcoin-cli -regtest -rpcuser=user -rpcpassword=pass generatetoaddress 100 mtDDKi5mDjZqGzmbnfUnVQ8ZhCPMPVsApj
```

Next, you can start some clients. To create a client, use the following command:

```
$ cargo run --bin noah -- --datadir ./test/noah1 create
$ cargo run --bin noah -- --datadir ./test/noah2 create
```

These will create individual wallets and print an onchain address you can use
to **fund them the same way as you did for the ASP above**. Note that clients
can receive offchain Ark transactions without having any onchain balance, but
a little bit of onchain money is needed to perform unilateral exits.

To use the onchain wallets, there are a few commands available:

```
$ NOAH2_ADDR=$(cargo run --bin noah -- --datadir ./test/noah2 get-address)
$ cargo run --bin noah -- --datadir ./test/noah1 send-onchain $NOAH2_ADDR "0.1 btc"
$ cargo run --bin noah -- --datadir ./test/noah2 balance
```

Once we have money, we can onboard into the Ark, afterwards the balance will
also show an offchain element.

```
$ cargo run --bin noah -- --datadir ./test/noah1 onboard "1 btc"
$ cargo run --bin noah -- --datadir ./test/noah1 balance
```

Remember that all txs will just be in the mempool if you don't generate blocks
once a while...

```
$ bitcoin-cli -regtest -rpcuser=user -rpcpassword=pass generatetoaddress 1 mtDDKi5mDjZqGzmbnfUnVQ8ZhCPMPVsApj
```

Then, let's send some money offchain to a third wallet:

```
$ cargo run --bin noah -- --datadir ./test/noah3 create
$ cargo run --bin noah -- --datadir ./test/noah3 balance
# Should be empty..
$ NOAH3_PK=$(cargo run --bin noah -- --datadir ./test/noah3 get-vtxo-pubkey)
# For now every client has just a single pubkey.
$ echo "${NOAH3_PK}"
$ cargo run --bin noah -- --datadir ./test/noah1 send ${NOAH3_PK} "0.1 btc"
$ cargo run --bin noah -- --datadir ./test/noah3 balance
```

You will notice that there is a slight delay when sending, this is because the
client needs to wait for the start of the next round and currently no
out-of-round payments are supported. The round interval can be changed in the
arkd configuration.

The `send` command is smart enough to understand onchain addresses:

```
$ NOAH3_ONCHAIN_ADDRESS=$(cargo run --bin noah -- --datadir ./test/noah3 get-address)
$ cargo run --bin noah -- --datadir ./test/noah1 send ${NOAH3_ONCHAIN_ADDRESS} "0.1 btc"
# sends 0.1 btc from noah1's VTXO balance to noah3 onchain address
```

User `noah1` can leave the ark collaboratively (i.e. ASP needs to collaborate):

```
$ NOAH1_ONCHAIN_ADDRESS=$(cargo run --bin noah -- --datadir ./test/noah1 get-address)
$ cargo run --bin noah -- --datadir ./test/noah1 send ${NOAH3_ONCHAIN_ADDRESS} "0.899 btc"
# leaving some change to pay fees
```

In the case of the ASP is not responding, `noah1` can leave the ark unilaterally:

```
$ cargo run --bin noah -- --datadir ./test/noah1 start-exit
# must wait for 12 blocks (see vtxo_exit_delta in arkd configuration)
$ bitcoin-cli -regtest -rpcuser=user -rpcpassword=pass generatetoaddress 13 mtDDKi5mDjZqGzmbnfUnVQ8ZhCPMPVsApj
$ cargo run --bin noah -- --datadir ./test/noah1 claim-exit
```

You can see all available commands with `help`:

```
$ cargo run --bin noah -- --datadir ./test/noah1 help
```
