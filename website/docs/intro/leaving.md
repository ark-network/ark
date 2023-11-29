---
sidebar_position: 5
title: 'Leaving the Ark'
---

### Overview

Alice wants to leave the Ark and get her funds back on-chain. It requires an on-chain transaction.

### Timeline of events

1. Alice tells ASP she wants to trade [VTXO](./nomenclature#vtxo-1) for UTXO
2. ASP (with Alice) prepares next [Pool transaction](./nomenclature#pool-transaction-aka-ark-transaction):
   - an additional output is added, locked to `Alice`
3. Alice creates a [Forfeit transaction](./nomenclature#forfeit-transaction-):
   - spends from VTXO (1) with `Alice + ASP`
   - adds connector output from Pool transaction (2) as input
   - signs it and send it to the ASP
4. ASP broadcasts [Pool transaction](./nomenclature#pool-transaction-aka-ark-transaction)
5. Alice has now a new UTXO
6. For at most 4 weeks, Alice will be able to double spend her’s [VTXO](./nomenclature#vtxo-1), but if she does it, the ASP will have time (24 hours) to grab the funds from the [VTXO](./nomenclature#vtxo-1) to itself using the [Forfeit transaction](./nomenclature#forfeit-transaction-)
