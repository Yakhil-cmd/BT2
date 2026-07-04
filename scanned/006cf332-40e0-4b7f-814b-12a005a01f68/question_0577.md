# Q0577: Validator Strk Reward Claim checkpoint rollover

## Question
Can an unprivileged attacker use `claim_rewards(staker_address)` after an exit intent but before the action in one validator with one STRK delegation pool to make a later claim path observe stale or double-advanced checkpoints in `staker_info.unclaimed_rewards_own, reward supplier balance, reward_address`, causing rewards to be skipped, double-counted, or sent to an address that no longer matches the intended beneficiary?

## Target
- File/function: src/staking/staking.cairo::claim_rewards
- Entrypoint: claim_rewards(staker_address)
- Attacker controls: caller as staker or reward address, chosen staker_address, claim timing relative to updates and address changes
- Exploit idea: Interleave `claim_rewards(staker_address)` with a reward claim or pool switch and inspect whether the checkpoint update order around `send_rewards_to_staker / claim_from_reward_supplier` leaves an old reward recipient or claim cursor active for one extra transition.
- Invariant to test: Each reward unit should be claimable exactly once by the current authorized beneficiary, and checkpoint advancement should be monotonic and single-use.
- Expected Immunefi impact: High - Theft of unclaimed yield
- Fast validation: Build a two- or three-step PoC that changes the beneficiary state, claims once, then repeats the nearest follow-up action and asserts that no extra reward becomes claimable and no reward is stranded.
