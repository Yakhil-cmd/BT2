# Q1412: Initial Delegation Into A Pool reward-math edge

## Question
Can an unprivileged attacker use `enter_delegation_pool(reward_address, amount)` across the i to i+k latency boundary in one validator with both STRK and BTC-wrapper pools with an amount that empties the live balance except for one unit to create repeated micro-cycles that maximize rounding loss in `compute_rewards_rounded_down`, so that `set_member_balance / transfer_to_staking_contract` reads or writes `pool_member_info, pool_member_epoch_balance, cumulative_rewards_trace` in a way that breaks conservation between rewards forwarded to the pool and rewards claimable by members?

## Target
- File/function: src/pool/pool.cairo::enter_delegation_pool
- Entrypoint: enter_delegation_pool(reward_address, amount)
- Attacker controls: caller as delegator, reward_address, amount, token type of the pool, join timing
- Exploit idea: Accumulate the exact checkpoint pattern described, then claim from the pool member and compare the realized rewards and gas use against a bounded reference.
- Invariant to test: The pool reward path should preserve conservation between rewards forwarded to the pool and rewards claimable by members even when the member trace contains many updates or old-version checkpoint shapes.
- Expected Immunefi impact: Medium - Griefing (e.g. no profit motive for an attacker, but damage to the users or the protocol)
- Fast validation: Generate the edge trace with scripted deposits, exits, and switches; then run a claim and assert bounded gas plus exact reward conservation within the tolerated rounding policy.
