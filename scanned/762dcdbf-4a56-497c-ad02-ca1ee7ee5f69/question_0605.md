# Q0605: Delegation Pool Switch checkpoint rollover

## Question
Can an unprivileged attacker use `switch_delegation_pool(to_staker, to_pool, amount)` immediately after a claim in one validator with one STRK delegation pool to make a later claim path observe stale or double-advanced checkpoints in `pool_member_info.unpool_amount, pool_member_info.reward_address, staking delegated traces`, causing rewards to be skipped, double-counted, or sent to an address that no longer matches the intended beneficiary?

## Target
- File/function: src/pool/pool.cairo::switch_delegation_pool
- Entrypoint: switch_delegation_pool(to_staker, to_pool, amount)
- Attacker controls: caller as pool_member, to_staker, to_pool, amount, serialized switch data timing
- Exploit idea: Interleave `switch_delegation_pool(to_staker, to_pool, amount)` with a reward claim or pool switch and inspect whether the checkpoint update order around `switch_staking_delegation_pool / enter_delegation_pool_from_staking_contract` leaves an old reward recipient or claim cursor active for one extra transition.
- Invariant to test: Each reward unit should be claimable exactly once by the current authorized beneficiary, and checkpoint advancement should be monotonic and single-use.
- Expected Immunefi impact: High - Theft of unclaimed yield
- Fast validation: Build a two- or three-step PoC that changes the beneficiary state, claims once, then repeats the nearest follow-up action and asserts that no extra reward becomes claimable and no reward is stranded.
