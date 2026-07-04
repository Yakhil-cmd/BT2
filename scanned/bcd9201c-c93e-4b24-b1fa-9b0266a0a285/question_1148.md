# Q1148: Block reward allocation to zero-per-unit pools

## Question
Can an unprivileged attacker call `update_rewards(staker_address, disable_rewards)` against a validator with a large STRK pool and no BTC pool across the i to i+k latency boundary and make the function take a path that forwards STRK to a pool whose `compute_rewards_per_unit` returns zero because the pool balance is below `min_delegation_for_rewards`, causing `last_reward_block, block_rewards, staker_info.unclaimed_rewards_own, pool rewards, reward supplier debt` to diverge from the actual claimable reward state?

## Target
- File/function: src/staking/staking.cairo::update_rewards
- Entrypoint: update_rewards(staker_address, disable_rewards)
- Attacker controls: arbitrary caller, chosen staker_address, caller-chosen disable_rewards flag, per-block call ordering
- Exploit idea: Force the chosen validator through the edge state, call the public reward update from an unrelated account, and compare the pool-level and staker-level reward state before and after the bridge funding side effects.
- Invariant to test: pool rewards can be forwarded to a pool only if that pool has a non-zero claimable path for members or a documented sink
- Expected Immunefi impact: High - Permanent freezing of unclaimed yield
- Fast validation: Model the same block sequence off-chain, then assert the on-chain staker rewards, pool rewards, and reward-supplier debt all remain jointly conserved.
