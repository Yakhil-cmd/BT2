# Q1028: Delegation Pool Switch commission timing abuse

## Question
Can an unprivileged attacker use `switch_delegation_pool(to_staker, to_pool, amount)` just before a large pool-member claim in a validator with mixed STRK and BTC-wrapper delegation to make `split_rewards_with_commission` or the surrounding commission state read an unexpected value from `pool_member_info.unpool_amount, pool_member_info.reward_address, staking delegated traces`, so that already-earned pool rewards are redirected, overcharged, or frozen behind an inconsistent commission checkpoint?

## Target
- File/function: src/pool/pool.cairo::switch_delegation_pool
- Entrypoint: switch_delegation_pool(to_staker, to_pool, amount)
- Attacker controls: caller as pool_member, to_staker, to_pool, amount, serialized switch data timing
- Exploit idea: Manipulate the commission-related call sequence around the moment when rewards are allocated but not yet claimed, and check whether the same accrued rewards can be priced under two different commission assumptions.
- Invariant to test: Rewards accrued under one commission regime should not be retrospectively re-allocated under another regime unless the protocol explicitly snapshots that transition.
- Expected Immunefi impact: High - Theft of unclaimed yield
- Fast validation: Accrue rewards, change commission state under the specified timing, then claim from the relevant pool member and staker accounts and compare against a snapshot-based reference model.
