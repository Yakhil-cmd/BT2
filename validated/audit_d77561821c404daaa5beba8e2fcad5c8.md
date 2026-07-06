Based on my analysis, K = 2 in `src/constants.cairo`, so `K - 1 = 1`, meaning the `set_member_balance` code `cumulative_rewards_trace_length() + 1` is actually correct (matching the comment's formula `+ (K - 1)`). That is not a bug.

Let me now look more carefully at the reward accounting in pool.cairo's `claim_rewards` and the `update_pool_rewards` flow in staking.cairo.