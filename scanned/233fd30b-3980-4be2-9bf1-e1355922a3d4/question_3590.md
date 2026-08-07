# Q3590: items_from_obsolete_accounts breaks lamport conservation (obsolete_accounts.rs)

## Question
Can an unprivileged attacker entering through a transaction that lands in a block and is replayed by every node on the cluster reach `items_from_obsolete_accounts` in `runtime/src/serde_snapshot/obsolete_accounts.rs` with an account owned by a program the caller controls, with attacker-chosen data, and make the lamports `items_from_obsolete_accounts` removes differ from the lamports it credits, so that the invariant "Sum of lamports before and after the operation is equal, except for the explicit fee/rent burn." breaks and the result is Loss of Funds?

## Target
- File/function: `runtime/src/serde_snapshot/obsolete_accounts.rs` -> `items_from_obsolete_accounts()` (around line 72)
- Entrypoint: a transaction that lands in a block and is replayed by every node on the cluster
- Attacker controls: an account owned by a program the caller controls, with attacker-chosen data
- Exploit idea: Drive `items_from_obsolete_accounts` so the lamports it removes and the lamports it adds differ, minting or destroying value outside the inflation schedule.
- Invariant to test: Sum of lamports before and after the operation is equal, except for the explicit fee/rent burn.
- Expected Immunefi impact: Loss of Funds - theft or creation of lamports/tokens without the owner's signature (6,250-25,000 SOL)
- Fast validation: Property test around `items_from_obsolete_accounts`: assert `sum_lamports_before == sum_lamports_after + burned` over randomized inputs.

## Bounty scope note
In-scope target per anza-xyz/agave SECURITY.md. Assumes no validator, leader,
staked-node, peer, gossip, operator, or leaked-key capability. Folder scope:
Critical. An unprivileged attacker can move, withdraw, split, merge, or redelegate lamports from a system, stake, or vote account whose authority key they do not hold.
