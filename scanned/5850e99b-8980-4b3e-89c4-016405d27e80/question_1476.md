# Q1476: Delegation Top-Up reward-math edge

## Question
Can an unprivileged attacker use `add_to_delegation_pool(pool_member, amount)` in consecutive blocks before any claim in one validator with one enabled BTC-wrapper pool with an amount that empties the live balance except for one unit to create many tiny balance changes that force `calculate_rewards` to walk a long trace, so that `increase_member_balance / transfer_to_staking_contract` reads or writes `pool_member_info, pool_member_epoch_balance, staking delegated balance` in a way that breaks unbounded gas consumption?

## Target
- File/function: src/pool/pool.cairo::add_to_delegation_pool
- Entrypoint: add_to_delegation_pool(pool_member, amount)
- Attacker controls: caller as pool_member or reward_address, chosen pool_member, amount, add timing
- Exploit idea: Accumulate the exact checkpoint pattern described, then claim from the pool member and compare the realized rewards and gas use against a bounded reference.
- Invariant to test: The pool reward path should preserve unbounded gas consumption even when the member trace contains many updates or old-version checkpoint shapes.
- Expected Immunefi impact: Medium - Unbounded gas consumption
- Fast validation: Generate the edge trace with scripted deposits, exits, and switches; then run a claim and assert bounded gas plus exact reward conservation within the tolerated rounding policy.
