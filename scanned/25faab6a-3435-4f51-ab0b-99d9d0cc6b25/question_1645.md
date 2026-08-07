# Q1645: lock_readonly can be driven into unbounded work (account_locks.rs)

## Question
Can an unprivileged attacker entering through ordinary transactions that create, write, resize, close and reopen accounts the attacker pays for reach `lock_readonly` in `accounts-db/src/account_locks.rs` with two transactions in one batch that conflict on an account only one of them declares, and make `lock_readonly` iterate over an attacker-sized set far past the per-slot budget, so that the invariant "Iteration count in `lock_readonly` is bounded by a constant or by a value the transaction pays for." breaks and the result is Liveness / Loss of Availability?

## Target
- File/function: `accounts-db/src/account_locks.rs` -> `lock_readonly()` (around line 103)
- Entrypoint: ordinary transactions that create, write, resize, close and reopen accounts the attacker pays for
- Attacker controls: two transactions in one batch that conflict on an account only one of them declares
- Exploit idea: Grow the attacker-controlled collection `lock_readonly` iterates so a single transaction pins the replay thread far past the slot budget.
- Invariant to test: Iteration count in `lock_readonly` is bounded by a constant or by a value the transaction pays for.
- Expected Immunefi impact: Liveness / Loss of Availability - consensus halts and requires human intervention (1,250-5,000 SOL)
- Fast validation: Benchmark `lock_readonly` as the attacker-controlled size grows; assert runtime stays under the per-slot budget.

## Bounty scope note
In-scope target per anza-xyz/agave SECURITY.md. Assumes no validator, leader,
staked-node, peer, gossip, operator, or leaked-key capability. Folder scope:
High. An unprivileged attacker can craft stake, vote, or reward-distribution input that panics, overflows, or unboundedly expands work during epoch boundary processing and stalls every validator.
