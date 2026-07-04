# Q2526: Delegation Exit Intent BTC precision boundary

## Question
Can an unprivileged attacker use `exit_delegation_pool_intent(amount)` in the last block of an epoch against an enabled BTC wrapper with the minimum allowed 5 decimals by executing repeated tiny top-ups followed by a full claim, and make normalization between native token amounts and 18-decimal internal amounts drift enough that `pool_member_info.unpool_amount, pool_member_info.unpool_time, pool_member_epoch_balance` no longer matches the actual pool or staking position?

## Target
- File/function: src/pool/pool.cairo::exit_delegation_pool_intent
- Entrypoint: exit_delegation_pool_intent(amount)
- Attacker controls: caller as pool member, amount, repeated partial intents, timing around staker unstake
- Exploit idea: Target the conversion points around `from_native_amount`, `to_native_amount`, and the reward base value chosen for BTC wrappers, looking for amounts that can be withdrawn, switched, or rewarded twice after normalization.
- Invariant to test: Native BTC-wrapper balances, normalized balances, and rewards must remain bijective up to documented rounding, regardless of the wrapper decimals.
- Expected Immunefi impact: Critical - Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Instantiate mocked enabled wrappers at the stated decimals, execute the sequence, and assert that the sum of claims, exits, and residual balances never exceeds the funded wrapper amount after normalization.
