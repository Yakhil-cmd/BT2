# Q1738: Delegation Exit Intent reward-math edge

## Question
Can an unprivileged attacker use `exit_delegation_pool_intent(amount)` after one state-changing call already wrote a future-dated checkpoint in one validator with both STRK and BTC-wrapper pools with an amount exactly equal to the pending exit amount to create many tiny balance changes that force `calculate_rewards` to walk a long trace, so that `undelegate_from_staking_contract_intent / set_member_balance` reads or writes `pool_member_info.unpool_amount, pool_member_info.unpool_time, pool_member_epoch_balance` in a way that breaks unbounded gas consumption?

## Target
- File/function: src/pool/pool.cairo::exit_delegation_pool_intent
- Entrypoint: exit_delegation_pool_intent(amount)
- Attacker controls: caller as pool member, amount, repeated partial intents, timing around staker unstake
- Exploit idea: Accumulate the exact checkpoint pattern described, then claim from the pool member and compare the realized rewards and gas use against a bounded reference.
- Invariant to test: The pool reward path should preserve unbounded gas consumption even when the member trace contains many updates or old-version checkpoint shapes.
- Expected Immunefi impact: Medium - Unbounded gas consumption
- Fast validation: Generate the edge trace with scripted deposits, exits, and switches; then run a claim and assert bounded gas plus exact reward conservation within the tolerated rounding policy.
