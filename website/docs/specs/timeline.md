---
sidebar_position: 3
title: 'Timeline'
---

### Onboarding the Ark

1. Alice creates a [Funding transaction](#funding-transaction):
   - adds any segwit output as an input (<u>must be segwit</u>)
   - adds output locked by `(Alice + ASP) or (ASP in 1 month)`
   - sends it to ASP, not signed
2. Alice receives a [Redeem transaction](#redeem-transaction-) from the ASP:
   - signed by the ASP, spends Funding transaction (1) via `Alice + ASP`
   - has one output locked by `(Alice + ASP) or (Alice in 24 hours)`
3. Alice signs and broadcasts Funding transaction (1)
   - Is now safe for Alice to broadcast this funding transaction because now she can leave anytime with
     [Redeem transaction](#redeem-transaction-) (2) spending `Alice in 24h`, i.e. Alice will be able to get
     her funds back in 24 hours.
4. ASP (with Alice) prepares next [Pool transaction](#pool-transaction-aka-ark-transaction)
5. Alice creates a [Forfeit transaction](#forfeit-transaction-):
   - spends from Redeem transaction (2) via `Alice + ASP`
   - adds connector output from Pool transaction (4) as input
   - signs (SIGHASH_ALL) and sends it to the ASP
6. ASP broadcasts [Pool transaction](#pool-transaction-aka-ark-transaction) (4)
7. Alice has now a [VTXO](#vtxo)
8. After 1 month ASP spends Funding transaction (1) via `ASP in 1 month`

### Payment to Bob

1. Alice tells ASP to send [VTXO](#vtxo) to Bob
2. ASP (with Alice) prepares next [Pool transaction](#pool-transaction-aka-ark-transaction)
3. Alice creates a [Forfeit transaction](#forfeit-transaction-):
   - spends from VTXO (1) via `Alice + ASP`
   - adds connector output from Pool transaction (2) as input
   - signs (SIGHASH_ALL) and sends it to the ASP
4. ASP broadcasts [Pool transaction](#pool-transaction-aka-ark-transaction)
5. Bob has now a new [VTXO](#vtxo)
6. For at most 4 weeks, Alice will be able to double spend her’s [VTXO](#vtxo), but if she does it, the ASP will have time to grab the funds from the [VTXO](#vtxo) to itself using the [Forfeit transaction](#forfeit-transaction-)

### Exiting the Ark

1. Alice tells ASP she wants to trade [VTXO](#vtxo) for UTXO
2. ASP (with Alice) prepares next [Pool transaction](#pool-transaction-aka-ark-transaction):
   - an additional output is added, locked by `Alice`
3. Alice creates a [Forfeit transaction](#forfeit-transaction-):
   - spends from VTXO (1) with `Alice + ASP`
   - adds connector output from Pool transaction (2) as input
   - signs it and send it to the ASP
4. ASP broadcasts [Pool transaction](#pool-transaction-aka-ark-transaction)
5. Alice has now a new UTXO
6. For at most 4 weeks, Alice will be able to double spend her’s [VTXO](#vtxo), but if she does it, the ASP will have time (24 hours) to grab the funds from the [VTXO](#vtxo) to itself using the [Forfeit transaction](#forfeit-transaction-)
