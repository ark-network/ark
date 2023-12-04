---
description: Detailed information about the protocol, guidance on providing liquidity, and instructions on how to efficiently spend your coins off-chain in a secure manner
sidebar_position: 1
slug: /
title: Introduction
---

**Welcome to Ark's developer hub.** Here, you'll find detailed information about the protocol, guidance on providing liquidity, and instructions on how to efficiently spend your coins off-chain in a secure manner.

<div align="center">
  <img src="/img/ark-banner.png" alt="Noah designing the ark to onboard Bitcoin users"/>
</div>

### 🤔 Why Ark?

Bitcoin is the world's most secure and censorship-resistant blockchain. However, it's not the fastest or the cheapest. Ark is a **second-layer solution** designed to **scale Bitcoin transactions**. It uses a shared UTXO model for confidential and off-chain payments through an intermediary server that cannot access your funds.

### 👶🏼 ELI5: Ark in Simple Terms

Consider the early private banks that issued banknotes in exchange for gold deposits. These banknotes were redeemable for gold at any time. The banknotes were more convenient to use than gold, but they were only as good as the bank that issued them. If the bank went bankrupt, the banknotes would become worthless.

When Alice **deposits Bitcoin with a server** (akin to a digital bank), she receives a digital check, similar to a banknote but with a crucial difference. This check is akin to **a cheque with an expiration date**.

The digital cheque Alice receives comes with an expiration date. To keep her funds secure and the cheque valid, she **must interact with the server at least once every month**. If Alice fails to do this, the server reserves the right to **claim the Bitcoin backing the cheque upon its maturity**.

She can use this check for payment with anyone else using the same digital bank, bypassing the need to use the Bitcoin blockchain. Before expiration, the check can be **redeemed** for Bitcoin, or it can be **refreshed** by interacting with the server.

Should the digital bank cease to exist, **users can still retrieve their digital gold without the bank's assistance**. This is similar to withdrawing gold from a defunct traditional bank, but in Ark's case, the process is enforced and automated by the Bitcoin blockchain. This ensures that your digital gold remains safe and accessible.

### 🔨 How Does it Work?

Start by exploring the [Nomenclature](/docs/learn/nomenclature.md) to familiarize yourself with key concepts and terminology. Then, learn how to [Board the Ark](/docs/learn/boarding.md), [Send Payments](/docs/learn/payments.md), and eventually [Leave the Ark](/docs/learn/leaving.md) to withdraw your funds back to the Bitcoin blockchain in case of server unresponsiveness.

### 🏃‍♀️ Running Ark

:::info
🚧 **Work in progress**
The Ark reference implementation is currently under development. Please check back soon for updates.
:::

You can join an existing Ark service provider or run your own.

- [Join an Ark as User](/user/intro.md)
- [Operate an Ark as Liquidity Provider](/provider/intro.md)

### 👩‍💻 Integrate Ark

:::info
🚧 **Work in progress**
The Ark libraries and developer tools are currently under development. Please check back soon for updates.
:::

You can [integrate Ark](/docs/developers/get-started.md) into your wallet or application to enable your users to send and receive Bitcoin payments off-chain.

### ⌨️ Contributing

We welcome contributions from the community. If you'd like to contribute to the reference implementation, please see the [Ark GitHub repository](https://github.com/ark-network/ark) repository.

### 🤓 Protocol Specifications

Follow the [BOATS GitHub repository](https://github.com/ark-network/boats) for updates.

### ➰ Stay in the Loop

- Join our community on [Telegram](https://t.me/ark_network_community).
- Ask questions or get help on [Stack Overflow](https://bitcoin.stackexchange.com/questions/tagged/ark).
- To propose protocol improvements, [open an issue on GitHub](https://github.com/ark-network/boats/issues/new).

### ⚖️ License

By contributing to this repository, you agree to license your work under the MIT license, unless specified otherwise. Contributions not originally authored by you must include a license header with the original author(s) and source.
