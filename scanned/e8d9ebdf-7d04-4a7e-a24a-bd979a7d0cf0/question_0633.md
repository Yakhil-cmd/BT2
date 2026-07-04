# Q0633: Delegation Exit Finalization checkpoint rollover

## Question
Can an unprivileged attacker use `exit_delegation_pool_action(pool_member)` after a reward-address change but before the next update in one validator with one STRK delegation pool to make a later claim path observe stale or double-advanced checkpoints in `pool_member_info.unpool_amount, pool_member_info.unpool_time, pool balance`, causing rewards to be skipped, double-counted, or sent to an address that no longer matches the intended beneficiary?

## Target
- File/function: src/pool/pool.cairo::exit_delegation_pool_action
- Entrypoint: exit_delegation_pool_action(pool_member)
- Attacker controls: caller, chosen pool_member, action timing after wait window, whether staker was already removed
- Exploit idea: Interleave `exit_delegation_pool_action(pool_member)` with a reward claim or pool switch and inspect whether the checkpoint update order around `remove_from_delegation_pool_action / checked_transfer` leaves an old reward recipient or claim cursor active for one extra transition.
- Invariant to test: Each reward unit should be claimable exactly once by the current authorized beneficiary, and checkpoint advancement should be monotonic and single-use.
- Expected Immunefi impact: High - Theft of unclaimed yield
- Fast validation: Build a two- or three-step PoC that changes the beneficiary state, claims once, then repeats the nearest follow-up action and asserts that no extra reward becomes claimable and no reward is stranded.
