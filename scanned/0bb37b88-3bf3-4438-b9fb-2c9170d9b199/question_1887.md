# Q1887: insert_map_only mishandles duplicate/aliased accounts (transaction_state_container.rs)

## Question
Can an unprivileged attacker entering through a transaction that lands in a block and is replayed by every node on the cluster reach `insert_map_only` in `core/src/banking_stage/transaction_scheduler/transaction_state_container.rs` with state that is committed on one fork and then observed from another, and have `insert_map_only` read a stale copy of an account passed twice in the same instruction, so that the invariant "Aliased account references observe a single coherent value throughout the instruction." breaks and the result is Loss of Funds?

## Target
- File/function: `core/src/banking_stage/transaction_scheduler/transaction_state_container.rs` -> `insert_map_only()` (around line 268)
- Entrypoint: a transaction that lands in a block and is replayed by every node on the cluster
- Attacker controls: state that is committed on one fork and then observed from another
- Exploit idea: Pass the same account at two indices so `insert_map_only` reads a stale copy and writes back a value computed from it, duplicating or erasing a balance.
- Invariant to test: Aliased account references observe a single coherent value throughout the instruction.
- Expected Immunefi impact: Loss of Funds - theft or creation of lamports/tokens without the owner's signature (6,250-25,000 SOL)
- Fast validation: Unit test the path with the same pubkey at two indices; assert the final lamports match the single-reference case.

## Bounty scope note
In-scope target per anza-xyz/agave SECURITY.md. Assumes no validator, leader,
staked-node, peer, gossip, operator, or leaked-key capability. Folder scope:
Critical. An unprivileged attacker can move, withdraw, split, merge, or redelegate lamports from a system, stake, or vote account whose authority key they do not hold.
