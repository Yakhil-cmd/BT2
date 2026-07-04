# Q2023: Delegator Reward Claim reward-math edge

## Question
Can an unprivileged attacker use `claim_rewards(pool_member)` in the last block of an epoch in one validator with one enabled BTC-wrapper pool with an amount split across many micro-transactions to create balance changes around the `find_sigma` edge cases where the stored trace index can be `len`, `len + 1`, or `1`, so that `calculate_rewards / find_sigma / get_current_checkpoint` reads or writes `reward_checkpoint, entry_to_claim_from, cumulative_rewards_trace, _unclaimed_rewards_from_v0` in a way that breaks single-use reward accounting?

## Target
- File/function: src/pool/pool.cairo::claim_rewards
- Entrypoint: claim_rewards(pool_member)
- Attacker controls: caller as pool_member or reward_address, chosen pool_member, claim timing, checkpoint count
- Exploit idea: Accumulate the exact checkpoint pattern described, then claim from the pool member and compare the realized rewards and gas use against a bounded reference.
- Invariant to test: The pool reward path should preserve single-use reward accounting even when the member trace contains many updates or old-version checkpoint shapes.
- Expected Immunefi impact: High - Theft of unclaimed yield
- Fast validation: Generate the edge trace with scripted deposits, exits, and switches; then run a claim and assert bounded gas plus exact reward conservation within the tolerated rounding policy.
