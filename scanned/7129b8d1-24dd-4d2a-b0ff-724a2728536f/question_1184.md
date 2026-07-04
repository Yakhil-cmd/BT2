# Q1184: Reward supplier debt amplification

## Question
Can an unprivileged attacker call `update_rewards(staker_address, disable_rewards)` against a validator with only self-stake in consecutive blocks before any claim and make the function take a path that repeatedly increases `unclaimed_rewards` and triggers `request_funds` faster than the bridge can settle pending debt, causing `last_reward_block, block_rewards, staker_info.unclaimed_rewards_own, pool rewards, reward supplier debt` to diverge from the actual claimable reward state?

## Target
- File/function: src/staking/staking.cairo::update_rewards
- Entrypoint: update_rewards(staker_address, disable_rewards)
- Attacker controls: arbitrary caller, chosen staker_address, caller-chosen disable_rewards flag, per-block call ordering
- Exploit idea: Force the chosen validator through the edge state, call the public reward update from an unrelated account, and compare the pool-level and staker-level reward state before and after the bridge funding side effects.
- Invariant to test: public updates should not let an unrelated caller create unbounded reward-supplier debt without a matching economic position
- Expected Immunefi impact: Medium - Griefing (e.g. no profit motive for an attacker, but damage to the users or the protocol)
- Fast validation: Model the same block sequence off-chain, then assert the on-chain staker rewards, pool rewards, and reward-supplier debt all remain jointly conserved.
