# Q2455: Initial Delegation Into A Pool BTC precision boundary

## Question
Can an unprivileged attacker use `enter_delegation_pool(reward_address, amount)` after one state-changing call already wrote a future-dated checkpoint against an enabled BTC wrapper with 18 decimals by executing a full undelegation followed by immediate redelegation into another BTC-wrapper pool, and make normalization between native token amounts and 18-decimal internal amounts drift enough that `pool_member_info, pool_member_epoch_balance, cumulative_rewards_trace` no longer matches the actual pool or staking position?

## Target
- File/function: src/pool/pool.cairo::enter_delegation_pool
- Entrypoint: enter_delegation_pool(reward_address, amount)
- Attacker controls: caller as delegator, reward_address, amount, token type of the pool, join timing
- Exploit idea: Target the conversion points around `from_native_amount`, `to_native_amount`, and the reward base value chosen for BTC wrappers, looking for amounts that can be withdrawn, switched, or rewarded twice after normalization.
- Invariant to test: Native BTC-wrapper balances, normalized balances, and rewards must remain bijective up to documented rounding, regardless of the wrapper decimals.
- Expected Immunefi impact: Critical - Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Instantiate mocked enabled wrappers at the stated decimals, execute the sequence, and assert that the sum of claims, exits, and residual balances never exceeds the funded wrapper amount after normalization.
