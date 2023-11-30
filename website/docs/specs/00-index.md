---
sidebar_position: 1
title: 'BOAT#0: Index'
---

# Index and Overview

Welcome! These **Basics of Ark Technology (BOAT)** documents describe the Ark protocol, a second layer solution that enables anonymous, off-chain payments through an untrusted intermediary that provides liquidity to the network.

## Index

- [BOAT #0: Index](00-index.md)

## Overview

Ark is a second-layer solution designed to help scale Bitcoin transactions by using a shared utxo model that enables anonymous, off-chain payments through an untrusted intermediary called the Ark Service Provider (**ASP**). ASPs are always-on servers that provide liquidity to the network, similar to how Lightning service providers work.

Ark has a utxo set that lives off the chain. These utxos are referred to as virtual utxos or **VTXOs** in short. VTXOs are like short-lived notes that expire after four weeks. Users must spend their VTXOs upon receiving them within this four-week timeframe or return them to themselves to reset the four-week timer.

Users can acquire VTXOs from someone who already owns them or use a process called **onboarding**, which is an atomic two-way peg mechanism that doesn't require trust. Onboarding lets users lift their on-chain utxos off the chain for a 1:1 virtual utxo. Users can unilaterally redeem a virtual utxo for an on-chain utxo without asking for ASP cooperation.

‍When sending funds, users coin-select and redeem their VTXOs and create new ones for the recipient (plus change) in a coinjoin round where ASP is the blinded coordinator. ASP funds the coinjoin with their own on-chain funds in exchange for VTXO redemptions. Therefore, the coinjoin transaction that hits on-chain has only one or a few inputs provided by the ASP.

The newly created VTXOs of the coinjoin round are bundled and nested under a shared transaction output. This shared output expires four weeks after its creation, and once it expires, the ASP who funded the shared output in the first place can solely sweep the shared output. All nested VTXOs under this shared output are expected to be redeemed in this window period.
