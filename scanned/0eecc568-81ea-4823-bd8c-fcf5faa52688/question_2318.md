# Q2318: Delegation Pool Switch reward-math edge

## Question
Can an unprivileged attacker use `switch_delegation_pool(to_staker, to_pool, amount)` after one state-changing call already wrote a future-dated checkpoint in many delegators sharing one validator reward schedule with an amount exactly equal to the pending exit amount to create balance changes around the `find_sigma` edge cases where the stored trace index can be `len`, `len + 1`, or `1`, so that `switch_staking_delegation_pool / enter_delegation_pool_from_staking_contract` reads or writes `pool_member_info.unpool_amount, pool_member_info.reward_address, staking delegated traces` in a way that breaks single-use reward accounting?

## Target
- File/function: src/pool/pool.cairo::switch_delegation_pool
- Entrypoint: switch_delegation_pool(to_staker, to_pool, amount)
- Attacker controls: caller as pool_member, to_staker, to_pool, amount, serialized switch data timing
- Exploit idea: Accumulate the exact checkpoint pattern described, then claim from the pool member and compare the realized rewards and gas use against a bounded reference.
- Invariant to test: The pool reward path should preserve single-use reward accounting even when the member trace contains many updates or old-version checkpoint shapes.
- Expected Immunefi impact: High - Theft of unclaimed yield
- Fast validation: Generate the edge trace with scripted deposits, exits, and switches; then run a claim and assert bounded gas plus exact reward conservation within the tolerated rounding policy.
