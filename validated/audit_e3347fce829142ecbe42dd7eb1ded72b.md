Looking at the `set_member_balance` function in `src/pool/pool.cairo`, there's a comment that says `cumulative_rewards_trace_idx` should be `len + (K - 1)`, but the code uses `len + 1`. Since `K = 2` (from `src/constants.cairo`), `K - 1 = 1`, so the code is actually correct for the current constant value.

Let me check the `update_pool_rewards` function to look for other accounting issues.