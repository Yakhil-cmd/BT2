# Q2721: Public Consensus Reward Update BTC precision boundary

## Question
Can an unprivileged attacker use `update_rewards(staker_address, disable_rewards)` in the last block of an epoch against an enabled BTC wrapper with 8 decimals by executing alternating add, exit-intent, and switch calls, and make normalization between native token amounts and 18-decimal internal amounts drift enough that `last_reward_block, block_rewards, staker_info.unclaimed_rewards_own, pool rewards, reward supplier debt` no longer matches the actual pool or staking position?

## Target
- File/function: src/staking/staking.cairo::update_rewards
- Entrypoint: update_rewards(staker_address, disable_rewards)
- Attacker controls: arbitrary caller, chosen staker_address, caller-chosen disable_rewards flag, per-block call ordering
- Exploit idea: Target the conversion points around `from_native_amount`, `to_native_amount`, and the reward base value chosen for BTC wrappers, looking for amounts that can be withdrawn, switched, or rewarded twice after normalization.
- Invariant to test: Native BTC-wrapper balances, normalized balances, and rewards must remain bijective up to documented rounding, regardless of the wrapper decimals.
- Expected Immunefi impact: Critical - Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Instantiate mocked enabled wrappers at the stated decimals, execute the sequence, and assert that the sum of claims, exits, and residual balances never exceeds the funded wrapper amount after normalization.
