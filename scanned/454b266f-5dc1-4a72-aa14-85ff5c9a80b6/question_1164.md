# Q1164: Cross-token staking-power drift during mixed STRK/BTC updates

## Question
Can an unprivileged attacker call `update_rewards(staker_address, disable_rewards)` against a validator with only self-stake in consecutive blocks before any claim and make the function take a path that reads stale active-token state while mixed STRK and BTC-wrapper balances cross the current epoch boundary, causing `last_reward_block, block_rewards, staker_info.unclaimed_rewards_own, pool rewards, reward supplier debt` to diverge from the actual claimable reward state?

## Target
- File/function: src/staking/staking.cairo::update_rewards
- Entrypoint: update_rewards(staker_address, disable_rewards)
- Attacker controls: arbitrary caller, chosen staker_address, caller-chosen disable_rewards flag, per-block call ordering
- Exploit idea: Force the chosen validator through the edge state, call the public reward update from an unrelated account, and compare the pool-level and staker-level reward state before and after the bridge funding side effects.
- Invariant to test: the same delegated amount must not be simultaneously excluded from total stake and included in the beneficiary's reward share
- Expected Immunefi impact: Medium - Material reward or staking-power accounting drift causing insolvency or unfair payouts
- Fast validation: Model the same block sequence off-chain, then assert the on-chain staker rewards, pool rewards, and reward-supplier debt all remain jointly conserved.
