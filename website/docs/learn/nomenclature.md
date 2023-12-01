---
sidebar_position: 1
title: 'Nomenclature'
---
:::info
🚧 This page is currently under development, and some concepts may not be entirely accurate. We greatly value your feedback and contributions. If you have any suggestions, corrections, or would like to submit edits, please do so through the pull request link available at the bottom of each page.
:::

## Intervenients

### ASP

ASPs are always-on servers that provide liquidity to the network, similar to how Lightning service providers work.

### Users

Any user that onboards the Ark or receives a payment inside an Ark.

### VTXO

Ark has a UTXO set that lives off the chain. These utxos are referred to as virtual UTXOs or VTXOs in short.

## Moments

### Boarding the Ark

When a User sends funds to the Ark and gets VTXOs in return.

### Unilateral exit

When a user decides to withdraw his funds from the Ark to mainchain, without asking the ASP for permission.

### Round

Periodic transaction crafted by the ASP that hits mainchain and creates new VTXOs.

## Transactions

**Note:** In an optimistic scenario, transactions marked with a **\*** should never hit onchain.

### Funding transaction

- When Alice wants to enter the Ark

| Inputs              | Outputs (locking script)            |
| ------------------- | ----------------------------------- |
| Alice’s segwit UTXO | `(Alice + ASP) or (ASP in 1 month)` |

### Redeem transaction\*

- Insurance for Alice, in case the ASP denies boarding on the Ark
- Allows Alice to receive funds back from the Ark after a grace period ie. 24 hours

| Inputs                                     | Outputs                                |
| ------------------------------------------ | -------------------------------------- |
| Funding transaction spending `Alice + ASP` | `(Alice + ASP) or (Alice in 24 hours)` |

### Forfeit transaction\*

- Insurance for the ASP, in case Alice tries to double spend her VTXO after spending it inside Ark
- Before the ASP funds Bob’s VTXO in the next Pool transaction, he must receive this transaction signed by Alice
- Uses a connector from the next Pool transaction to achieve atomicity

| Inputs                                    | Outputs |
| ----------------------------------------- | ------- |
| Redeem transaction spending `Alice + ASP` | `ASP`   |
| Connector from next Pool transaction      |

### Pool transaction (aka Ark transaction)

- Funded by the ASP, creates VTXOs
- After 4 weeks, the ASP can get their funds back
- Multisig `n-of-n` where `n` is the number of participants
- A new transaction is broadcasted every 5 seconds

| Inputs   | Outputs                                     |
| -------- | ------------------------------------------- |
| ASP UTXO | Shared output: `n-of-n or (ASP in 1 month)` |

### Shared output (aka Shared UTXO)

- Represents a binary tree of transactions
- In an optimistic scenario, this tree is never revealed

![Chart of a Shared Output](/img/shared_output.png)

### VTXO\*

- Similar to Redeem transaction
- Can be broadcasted anytime, on the condition that previous transactions on the transaction tree (up to the Pool transaction) are confirmed or broadcasted at the same time

| Inputs                                  | Outputs                                |
| --------------------------------------- | -------------------------------------- |
| Previous transaction on the binary tree | `(Alice + ASP) or (Alice in 24 hours)` |
