# Q0660: Validator Reward-Address Rollover checkpoint rollover

## Question
Can an unprivileged attacker use `change_reward_address(reward_address)` after an exit intent but before the action in many delegators sharing one validator reward schedule to make a later claim path observe stale or double-advanced checkpoints in `staker_info.reward_address, unclaimed_rewards_own`, causing rewards to be skipped, double-counted, or sent to an address that no longer matches the intended beneficiary?

## Target
- File/function: src/staking/staking.cairo::change_reward_address
- Entrypoint: change_reward_address(reward_address)
- Attacker controls: caller, new reward_address, timing relative to claims and updates
- Exploit idea: Interleave `change_reward_address(reward_address)` with a reward claim or pool switch and inspect whether the checkpoint update order around `write_staker_info / send_rewards_to_staker` leaves an old reward recipient or claim cursor active for one extra transition.
- Invariant to test: Each reward unit should be claimable exactly once by the current authorized beneficiary, and checkpoint advancement should be monotonic and single-use.
- Expected Immunefi impact: High - Theft of unclaimed yield
- Fast validation: Build a two- or three-step PoC that changes the beneficiary state, claims once, then repeats the nearest follow-up action and asserts that no extra reward becomes claimable and no reward is stranded.
