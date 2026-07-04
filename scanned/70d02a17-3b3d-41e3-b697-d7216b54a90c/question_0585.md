# Q0585: Delegator Reward Claim checkpoint rollover

## Question
Can an unprivileged attacker use `claim_rewards(pool_member)` immediately after a claim in one validator with one STRK delegation pool to make a later claim path observe stale or double-advanced checkpoints in `reward_checkpoint, entry_to_claim_from, cumulative_rewards_trace, _unclaimed_rewards_from_v0`, causing rewards to be skipped, double-counted, or sent to an address that no longer matches the intended beneficiary?

## Target
- File/function: src/pool/pool.cairo::claim_rewards
- Entrypoint: claim_rewards(pool_member)
- Attacker controls: caller as pool_member or reward_address, chosen pool_member, claim timing, checkpoint count
- Exploit idea: Interleave `claim_rewards(pool_member)` with a reward claim or pool switch and inspect whether the checkpoint update order around `calculate_rewards / find_sigma / get_current_checkpoint` leaves an old reward recipient or claim cursor active for one extra transition.
- Invariant to test: Each reward unit should be claimable exactly once by the current authorized beneficiary, and checkpoint advancement should be monotonic and single-use.
- Expected Immunefi impact: High - Theft of unclaimed yield
- Fast validation: Build a two- or three-step PoC that changes the beneficiary state, claims once, then repeats the nearest follow-up action and asserts that no extra reward becomes claimable and no reward is stranded.
