---
sidebar_position: 1
title: 'clArk'
toc_max_heading_level: 5
---

:::info
🚧 This page is currently under development, and some concepts may not be entirely accurate. We greatly value your feedback and contributions. If you have any suggestions, corrections, or would like to submit edits, please do so through the pull request link available at the bottom of each page.
:::

## Covenant-less Ark

This page describes a variant of Ark that doesn't need a covenant primitive in
the underlying block-chain but that uses pre-signed transactions to simulate
the effect of a covenant.


## Co-signing vs covenants

Instead of using a covenant primitive, which allows deterministic encoding of
child transactions and encoding them inside the output scripts of the parent
output. This is very practical because it means that the ASP can encode
commitments to these transactions and then send them to the users who can in
their turn deterministically verify that all the correct child transactions
have been committed.

When using pre-signed transactions, these transactions can't just be simply
encoded, but have to be actually created and then co-signed by a number of
participants and the signatures for each of these transactions have to be
stored in order for them to be valid.

### Which co-signers?

Since we will be emulating a simple covenant, i.e. enforcing a single spend
path, we will be pre-signing transactions and try to minimize the chance that
an alternative transaction can be signed because this will effectively break
the covenant.

The most obvious approach to this would be to include in the co-signer set all
parties that will rely on the covenant. If 100% of the stakeholders in the
covenant need to provide a signature to break it, it won't ever be broken so
long as any of the stakeholders wants the covenant to hold.

#### Receivers sign

In the context of the VTXO tree in Ark, this would mean that all owners of the
leaves of the trees have to sign all the transactions on the nodes between
their leaf and the root, and the ASP has to sign all transactions as well. This
poses an obvious difficulty though: it requires that these receivers are online
at the time of receiving and it requires that they actively participate in the
Ark round. As opposed to only the signers having to participate to sign their
forfeit transactions.

#### Senders sign

There is an interesting alternative, though. Like we discussed above, we want
to minimize the chance that the covenant gets broken, but we are struggling
with the requirement that all receivers have to show up for the Ark round.

But interestingly, during an Ark round, we already require a lot of
interactions with all the **senders** in the round. They have to participate in
the round because they have to sign their forfeit transactions. So what if all
the senders of the entire round and the ASP become the co-signers of all
pre-signed transactions? As long as a single signer behaves honestly (i.e.
removes their cosign key or at least never double-spends any of the signed
transactions), the simulated covenant will hold.

This is the version of clArk we will present in this document: the version
where all signers in the round not only sign their forfeit transactions, but at
the same time become co-signers of the entire VTXO tree.


## Onboarding

As opposed to a non-interactive covenant onboard, the cosign onboard will be
interactive. This is because the transaction for the unilateral exit has to be
cosigned by the ASP. This is called the reveal tx and it is identical to the
leaf txs of the VTXO trees.

A user that wants to on-board will ask the ASP to cosign this reveal tx. The
ASP does not have to do any real checks on it while signing. Only when the user
tries to spend the on-board VTXO in a round, the ASP will have to check the
user side of the signature.


## Rounds and Transactions

The flow of how the Ark rounds work in clArk is very similar to covenant Ark.
There is one extra step: the step in which all participants, i.e. all senders
plus the ASP, cosign the entire VTXO tree.

The steps are as follows:

- Users inform the ASP of which inputs they want to spend and which outputs
  they want to create.
  - Together with this, they create a new temporary keypair to use for the VTXO
    tree signing and attach it together a series of pre-generated MuSig2
    signing nonces that they will use to sign the VTXO tree.

- The ASP collects all this information, creates an unsigned round tx and an
  unsigned VTXO tree. It sends this info to the users in a "VTXO proposal".
  - It also generates its own signing nonces and uses the nonces provided by
    the users to calculate the aggregate nonces for all signatures in the
    entire tree.
  - It also provides the users with all the public keys of all cosigners.

- The users validate that their desired outputs are included in the tree and
  that their cosigning public key is included in the list of cosigners.
  - They proceed to sign all the txs in the VTXO tree using the aggregated
    nonces and all the cosigner public keys.

- The ASP aggregates all the partial signatures for the VTXO tree transactions
  and as such constructs a fully signed VTXO tree.
  - It then generates their MuSig2 signing nonces for all the forfeit
    transactions for all participating input VTXOs.
  - It sends the entire signed VTXO tree and the forfeit nonces to the users.

- The users validate that the signed VTXO tree is still the same one that they
  signed before and they validate that all signatures are correct.
  - They then sign all forfeit transactions using the connectors and the nonces
    provided by the ASP. They send the finished forfeit signatures to the ASP.

- When the ASP collected all forfeit signatures, it signs the round tx and
  sends the public round information to all users: a copy of the signed VTXO
  tree and the signed round tx.



## Storage Requirements

A final big difference between clArk and covenant Ark is that in the VTXO tree,
the commitments to child transactions are the signatures of the transactions
and not the transaction templates. In Ark, child transactions are encoded into
the output covenants of the parent, so they can just be deterministically
created and spent as such.

In clArk, however, in order to create valid child transactions, they need to
have valid signatures. These signatures obviously can't be deterministically
generated, so they have to be stored. This means that additional data has to be
stored for users to have a safe exit path. For Ark, knowing all the VTXO leaves
and some tree-specific parameters is sufficient, while for clArk, the
signatures of the tree, or at least for your exit branch, have to be stored
alongside the other information.

