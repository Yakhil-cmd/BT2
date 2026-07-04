# Q2365: Delegation Pool Switch reward-math edge

## Question
Can an unprivileged attacker use `switch_delegation_pool(to_staker, to_pool, amount)` in the first block of a new epoch in one validator with both STRK and BTC-wrapper pools with a dust-sized amount just above zero to create repeated micro-cycles that maximize rounding loss in `compute_rewards_rounded_down`, so that `switch_staking_delegation_pool / enter_delegation_pool_from_staking_contract` reads or writes `pool_member_info.unpool_amount, pool_member_info.reward_address, staking delegated traces` in a way that breaks conservation between rewards forwarded to the pool and rewards claimable by members?

## Target
- File/function: src/pool/pool.cairo::switch_delegation_pool
- Entrypoint: switch_delegation_pool(to_staker, to_pool, amount)
- Attacker controls: caller as pool_member, to_staker, to_pool, amount, serialized switch data timing
- Exploit idea: Accumulate the exact checkpoint pattern described, then claim from the pool member and compare the realized rewards and gas use against a bounded reference.
- Invariant to test: The pool reward path should preserve conservation between rewards forwarded to the pool and rewards claimable by members even when the member trace contains many updates or old-version checkpoint shapes.
- Expected Immunefi impact: Medium - Griefing (e.g. no profit motive for an attacker, but damage to the users or the protocol)
- Fast validation: Generate the edge trace with scripted deposits, exits, and switches; then run a claim and assert bounded gas plus exact reward conservation within the tolerated rounding policy.
