---
sidebar_position: 2
title: 'Boarding the Ark'
---

### Overview

Alice wants to board the Ark of a well-known Ark service provider (ASP). It requires an on-chain transaction.

Depending the type of [Boarding transaction](./nomenclature#boarding-transaction) chosen by the ASP, the timeline is different.

### 🧳 With luggage

- Alice must be online **at least once every 4 weeks** to keep her funds safe
- If ASP is unresponsive, Alice can claim her funds back in **24 hours**
- Easier for the ASP since all VTXOs are born equal

#### Timeline of events

1. Alice creates a [Boarding transaction](./nomenclature#with-luggage)
2. Alice adds any inputs she wants to cover the values the [VTXO](./nomenclature#vtxo-1) she will receive, plus on-chain fees
3. Alice adds an output with **2 spending paths**:
   - This funds will belong to the ASP after 4 weeks:
     - `(ASP after 4w)`
   - A covenant output that forces coins to be spent by a [VTXO](./nomenclature#vtxo) with an output with **2** spending paths:
     - `(Alice + ASP)`
     - `(Alice after 24h)`
4. Alice notifies ASP about the [Boarding transaction](./nomenclature#with-luggage)
5. Alice has now a promise of a [VTXO](./nomenclature#vtxo-1) enforced by a covenant

### Without luggage

- Alice don't need to worry about loosing funds after boarding
- If ASP is unresponsive, Alice can claim her funds back in **1 year**
- ASP must be aware of the timeout on the [Boarding transaction](./nomenclature#with-luggage) to prevent double spending

#### Timeline of events

1. Alice creates a [Boarding transaction](./nomenclature#without-luggage)
2. Alice adds any inputs she wants to cover the values the [VTXO](./nomenclature#vtxo-1) she will receive, plus on-chain fees.
3. Alice adds an output that forces coins to be spent by a [VTXO](./nomenclature#vtxo):
   - `(Alice + ASP)`
   - `(Alice after 1y)`
4. Alice notifies ASP about the [Boarding transaction](./nomenclature#withput-luggage)
5. Alice has now an onchain [VTXO](./nomenclature#vtxo-1)
