---
sidebar_position: 3
title: 'Boarding the Ark'
---

### Overview

Alice wants to board the Ark of a well-known Ark service provider (ASP). It requires an on-chain transaction.

- Alice must be online **at least once every 4 weeks** to keep her funds safe.
- If ASP denies Alice's boarding request, Alice can claim her funds back in 24 hours.

### The timeline of events

1. Alice creates a [Funding transaction](/docs/nomenclature#funding-transaction)

2. Alice adds any inputs she wants to cover the values the [VTXO](/docs/nomenclature#vtxo-1) she will receive, plus on-chain fees.

3. Alice adds an output with **two spending conditions**:

   - `(ASP in 1 month)`
   - A covenant output that forces coins to be spent by a [Redeem transaction](/docs/nomenclature#redeem-transaction) with an output with **two** spending conditions:
     - `(Alice + ASP)`
     - `(Alice in 24 hours)`

4. Alice notifies ASP about the [Funding transaction](/docs/nomenclature#funding-transaction)

5. Alice has now a [VTXO](/docs/nomenclature#vtxo-1).
