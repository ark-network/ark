---
sidebar_position: 2
title: 'Boarding the Ark'
---

### Overview

Alice wants to board the Ark of a well-known Ark service provider (ASP). It requires an on-chain transaction.

- Alice must be online **at least once every 4 weeks** to keep her funds safe.
- If ASP is unresponsive, Alice can claim her funds back in 24 hours.

### Timeline of events

1. Alice creates a [Funding transaction](./nomenclature#funding-transaction)

2. Alice adds any inputs she wants to cover the values the [VTXO](./nomenclature#vtxo-1) she will receive, plus on-chain fees.

3. Alice adds an output with **two spending conditions**:

   - `(ASP in 1 month)`
   - A covenant output that forces coins to be spent by a [Redeem transaction](./nomenclature#redeem-transaction) with an output with **two** spending conditions:
     - `(Alice + ASP)`
     - `(Alice in 24 hours)`

4. Alice notifies ASP about the [Funding transaction](./nomenclature#funding-transaction)

5. Alice has now a [VTXO](./nomenclature#vtxo-1).
