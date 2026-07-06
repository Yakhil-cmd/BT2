### Title
Consensus-mode `update_rewards` passes staker's own balance as `strk_total_stake` instead of total system stake, causing massive reward over-distribution - (File: src/staking/staking.cairo)

### Summary

In `StakingRewardsManagerImpl::update_rewards`, the staker's individual STRK and BTC balances are passed as `strk_total_stake` / `btc_total_stake` to `_update_rewards`. In contrast, `StakingAttestationImpl::update_rewards_from_attestation_contract` correctly passes the total system-wide stake for the same parameters. Because `_update_rewards` uses these values as the denominator when computing each staker's proportional reward share, consensus-mode reward calls give each staker 100 % of block rewards instead of their proportional fraction, draining the `RewardSupplier` and causing protocol insolvency.

### Finding Description

**Pre-consensus path** (`update_rewards_from_attestation_contract`, lines 1