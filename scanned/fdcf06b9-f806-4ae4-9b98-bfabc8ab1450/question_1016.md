# Q1016: Delegator Reward Claim commission timing abuse

## Question
Can an unprivileged attacker use `claim_rewards(pool_member)` just after a partial undelegation intent in a validator with mixed STRK and BTC-wrapper delegation to make `split_rewards_with_commission` or the surrounding commission state read an unexpected value from `reward_checkpoint, entry_to_claim_from, cumulative_rewards_trace, _unclaimed_rewards_from_v0`, so that already-earned pool rewards are redirected, overcharged, or frozen behind an inconsistent commission checkpoint?

## Target
- File/function: src/pool/pool.cairo::claim_rewards
- Entrypoint: claim_rewards(pool_member)
- Attacker controls: caller as pool_member or reward_address, chosen pool_member, claim timing, checkpoint count
- Exploit idea: Manipulate the commission-related call sequence around the moment when rewards are allocated but not yet claimed, and check whether the same accrued rewards can be priced under two different commission assumptions.
- Invariant to test: Rewards accrued under one commission regime should not be retrospectively re-allocated under another regime unless the protocol explicitly snapshots that transition.
- Expected Immunefi impact: High - Theft of unclaimed yield
- Fast validation: Accrue rewards, change commission state under the specified timing, then claim from the relevant pool member and staker accounts and compare against a snapshot-based reference model.
