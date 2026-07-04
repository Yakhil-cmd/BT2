# Q1233: Initial Delegation Into A Pool reward-math edge

## Question
Can an unprivileged attacker use `enter_delegation_pool(reward_address, amount)` in consecutive blocks before any claim in one validator with one enabled BTC-wrapper pool with a dust-sized amount just above zero to create many tiny balance changes that force `calculate_rewards` to walk a long trace, so that `set_member_balance / transfer_to_staking_contract` reads or writes `pool_member_info, pool_member_epoch_balance, cumulative_rewards_trace` in a way that breaks unbounded gas consumption?

## Target
- File/function: src/pool/pool.cairo::enter_delegation_pool
- Entrypoint: enter_delegation_pool(reward_address, amount)
- Attacker controls: caller as delegator, reward_address, amount, token type of the pool, join timing
- Exploit idea: Accumulate the exact checkpoint pattern described, then claim from the pool member and compare the realized rewards and gas use against a bounded reference.
- Invariant to test: The pool reward path should preserve unbounded gas consumption even when the member trace contains many updates or old-version checkpoint shapes.
- Expected Immunefi impact: Medium - Unbounded gas consumption
- Fast validation: Generate the edge trace with scripted deposits, exits, and switches; then run a claim and assert bounded gas plus exact reward conservation within the tolerated rounding policy.
