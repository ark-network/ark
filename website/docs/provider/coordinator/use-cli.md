---
sidebar_position: 6
title: Use the CLI
---

Now that your CLI is configured to connect with the running Coordinator, let's take a look at what it makes you capable of.

### List pool transactions

You can retrieve the list of pool transactions made in a certain time range with:

```bash
$ coordinator pools --start --end
```

You can omit the `--end` flag if you want to retrieve all pool transactions from a certain time unitl now.

For each pool tx, you can see details like the txid, status, and amount of liquidity added to the Ark.

You can also list all pool transactions created so far with:

```bash
$ coordinator pools --all
```

Run `coordinators pools --help` to see the full list of available flags.

### Get pool transaction details

You can get details about a specific pool transaction with:

```bash
$ coordinator pool --id <txid>
```

### Register inputs and outptus

You can manually register the VTXOs you're going to spend and the related receivers with:

```bash
$ coordinator register --inputs '[{"txid": "<txid>", "vout": <vout>}]' --outputs '[{"pubkey": "<pubkey>", "amount": <amount>}]'
```

The Coordinator answers with a message containing the virtual (forfeit) transaction spending your coins and the list of all the new VTXOs created in the next round - including those you registered.

<!-- Ref to some toool that allows to revealing the congestion control tree -->

### Finalize input and outputs

Once you signed the virtual transaction you can send it back to the Coordinator and finalize the process with:

```bash
$ coordinator finalize --vtx <signed_vtx>
```

In response you get the id of the pool transaction that is going to be broadcasted by the server.
