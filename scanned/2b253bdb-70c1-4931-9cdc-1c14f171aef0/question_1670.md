# Q1670: Delegation Top-Up reward-math edge

## Question
Can an unprivileged attacker use `add_to_delegation_pool(pool_member, amount)` across the i to i+k latency boundary in many delegators sharing one validator reward schedule with an amount exactly equal to the pending exit amount to create repeated micro-cycles that maximize rounding loss in `compute_rewards_rounded_down`, so that `increase_member_balance / transfer_to_staking_contract` reads or writes `pool_member_info, pool_member_epoch_balance, staking delegated balance` in a way that breaks conservation between rewards forwarded to the pool and rewards claimable by members?

## Target
- File/function: src/pool/pool.cairo::add_to_delegation_pool
- Entrypoint: add_to_delegation_pool(pool_member, amount)
- Attacker controls: caller as pool_member or reward_address, chosen pool_member, amount, add timing
- Exploit idea: Accumulate the exact checkpoint pattern described, then claim from the pool member and compare the realized rewards and gas use against a bounded reference.
- Invariant to test: The pool reward path should preserve conservation between rewards forwarded to the pool and rewards claimable by members even when the member trace contains many updates or old-version checkpoint shapes.
- Expected Immunefi impact: Medium - Griefing (e.g. no profit motive for an attacker, but damage to the users or the protocol)
- Fast validation: Generate the edge trace with scripted deposits, exits, and switches; then run a claim and assert bounded gas plus exact reward conservation within the tolerated rounding policy.
