# Q1536: empty mishandles duplicate/aliased accounts (sorted_storages.rs)

## Question
Can an unprivileged attacker entering through ordinary transactions that create, write, resize, close and reopen accounts the attacker pays for reach `empty` in `accounts-db/src/sorted_storages.rs` with arguments that drive the path into its error branch after side effects were applied, and have `empty` read a stale copy of an account passed twice in the same instruction, so that the invariant "Aliased account references observe a single coherent value throughout the instruction." breaks and the result is Loss of Funds?

## Target
- File/function: `accounts-db/src/sorted_storages.rs` -> `empty()` (around line 25)
- Entrypoint: ordinary transactions that create, write, resize, close and reopen accounts the attacker pays for
- Attacker controls: arguments that drive the path into its error branch after side effects were applied
- Exploit idea: Pass the same account at two indices so `empty` reads a stale copy and writes back a value computed from it, duplicating or erasing a balance.
- Invariant to test: Aliased account references observe a single coherent value throughout the instruction.
- Expected Immunefi impact: Loss of Funds - theft or creation of lamports/tokens without the owner's signature (6,250-25,000 SOL)
- Fast validation: Unit test the path with the same pubkey at two indices; assert the final lamports match the single-reference case.

## Bounty scope note
In-scope target per anza-xyz/agave SECURITY.md. Assumes no validator, leader,
staked-node, peer, gossip, operator, or leaked-key capability. Folder scope:
Critical. An unprivileged attacker can move, withdraw, split, merge, or redelegate lamports from a system, stake, or vote account whose authority key they do not hold.
