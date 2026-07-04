# Q2464: Delegation Top-Up BTC precision boundary

## Question
Can an unprivileged attacker use `add_to_delegation_pool(pool_member, amount)` in consecutive blocks before any claim against an enabled BTC wrapper with the minimum allowed 5 decimals by executing alternating add, exit-intent, and switch calls, and make normalization between native token amounts and 18-decimal internal amounts drift enough that `pool_member_info, pool_member_epoch_balance, staking delegated balance` no longer matches the actual pool or staking position?

## Target
- File/function: src/pool/pool.cairo::add_to_delegation_pool
- Entrypoint: add_to_delegation_pool(pool_member, amount)
- Attacker controls: caller as pool_member or reward_address, chosen pool_member, amount, add timing
- Exploit idea: Target the conversion points around `from_native_amount`, `to_native_amount`, and the reward base value chosen for BTC wrappers, looking for amounts that can be withdrawn, switched, or rewarded twice after normalization.
- Invariant to test: Native BTC-wrapper balances, normalized balances, and rewards must remain bijective up to documented rounding, regardless of the wrapper decimals.
- Expected Immunefi impact: Critical - Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Instantiate mocked enabled wrappers at the stated decimals, execute the sequence, and assert that the sum of claims, exits, and residual balances never exceeds the funded wrapper amount after normalization.
