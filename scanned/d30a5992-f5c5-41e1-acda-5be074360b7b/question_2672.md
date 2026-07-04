# Q2672: Delegation Pool Switch BTC precision boundary

## Question
Can an unprivileged attacker use `switch_delegation_pool(to_staker, to_pool, amount)` in the first block of a new epoch against an enabled BTC wrapper with 8 decimals by executing a full undelegation followed by immediate redelegation into another BTC-wrapper pool, and make normalization between native token amounts and 18-decimal internal amounts drift enough that `pool_member_info.unpool_amount, pool_member_info.reward_address, staking delegated traces` no longer matches the actual pool or staking position?

## Target
- File/function: src/pool/pool.cairo::switch_delegation_pool
- Entrypoint: switch_delegation_pool(to_staker, to_pool, amount)
- Attacker controls: caller as pool_member, to_staker, to_pool, amount, serialized switch data timing
- Exploit idea: Target the conversion points around `from_native_amount`, `to_native_amount`, and the reward base value chosen for BTC wrappers, looking for amounts that can be withdrawn, switched, or rewarded twice after normalization.
- Invariant to test: Native BTC-wrapper balances, normalized balances, and rewards must remain bijective up to documented rounding, regardless of the wrapper decimals.
- Expected Immunefi impact: Critical - Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Instantiate mocked enabled wrappers at the stated decimals, execute the sequence, and assert that the sum of claims, exits, and residual balances never exceeds the funded wrapper amount after normalization.
