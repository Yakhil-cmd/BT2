# Q1299: Initial Delegation Into A Pool reward-math edge

## Question
Can an unprivileged attacker use `enter_delegation_pool(reward_address, amount)` after one state-changing call already wrote a future-dated checkpoint in one validator with one STRK delegation pool with an amount split across many micro-transactions to create balance changes around the `find_sigma` edge cases where the stored trace index can be `len`, `len + 1`, or `1`, so that `set_member_balance / transfer_to_staking_contract` reads or writes `pool_member_info, pool_member_epoch_balance, cumulative_rewards_trace` in a way that breaks single-use reward accounting?

## Target
- File/function: src/pool/pool.cairo::enter_delegation_pool
- Entrypoint: enter_delegation_pool(reward_address, amount)
- Attacker controls: caller as delegator, reward_address, amount, token type of the pool, join timing
- Exploit idea: Accumulate the exact checkpoint pattern described, then claim from the pool member and compare the realized rewards and gas use against a bounded reference.
- Invariant to test: The pool reward path should preserve single-use reward accounting even when the member trace contains many updates or old-version checkpoint shapes.
- Expected Immunefi impact: High - Theft of unclaimed yield
- Fast validation: Generate the edge trace with scripted deposits, exits, and switches; then run a claim and assert bounded gas plus exact reward conservation within the tolerated rounding policy.
