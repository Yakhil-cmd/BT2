# Q1010: Commission Commitment Scheduling commission timing abuse

## Question
Can an unprivileged attacker use `set_commission_commitment(max_commission, expiration_epoch)` when rewards have accrued but have not yet been claimed in a validator with mixed STRK and BTC-wrapper delegation to make `split_rewards_with_commission` or the surrounding commission state read an unexpected value from `staker_pool_info.commission_commitment, commission, current_epoch`, so that already-earned pool rewards are redirected, overcharged, or frozen behind an inconsistent commission checkpoint?

## Target
- File/function: src/staking/staking.cairo::set_commission_commitment
- Entrypoint: set_commission_commitment(max_commission, expiration_epoch)
- Attacker controls: caller as staker, max_commission, expiration_epoch, call timing around epoch rollovers
- Exploit idea: Manipulate the commission-related call sequence around the moment when rewards are allocated but not yet claimed, and check whether the same accrued rewards can be priced under two different commission assumptions.
- Invariant to test: Rewards accrued under one commission regime should not be retrospectively re-allocated under another regime unless the protocol explicitly snapshots that transition.
- Expected Immunefi impact: High - Theft of unclaimed yield
- Fast validation: Accrue rewards, change commission state under the specified timing, then claim from the relevant pool member and staker accounts and compare against a snapshot-based reference model.
