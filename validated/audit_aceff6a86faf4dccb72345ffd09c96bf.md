This confirms the design: `epoch_stakes` snapshots (used for `snapshot_epoch_vote_accounts` and `rewarded_epoch_vote_accounts`) are immutable, point-in-time copies captured once at each epoch's leader-schedule boundary via `update_epoch_stakes`, which is only invoked during `process_new_epoch` at slot transitions [1](#0-0) . A transaction executed "late in an epoch" mutates the live `stakes_cache`, but `stakes_cache` is never consulted for `commission_bps` when `delay_commission_updates` is active — only the frozen `snapshot_epoch_vote_accounts` / `rewarded_epoch_vote_accounts` maps stored in `self.epoch_stakes` are read [2](#0-1) . [3](#0-2) [4](#0-3)

### Citations

**File:** runtime/src/bank.rs (L1855-1860)
```rust
        // Save a snapshot of stakes for use in consensus and stake weighted networking
        let leader_schedule_epoch = self.epoch_schedule.get_leader_schedule_epoch(slot);
        let (_, update_epoch_stakes_time_us) = measure_us!(self.update_epoch_stakes(
            leader_schedule_epoch,
            Some(filtered_distribution_vote_accounts),
        ));
```

**File:** runtime/src/bank.rs (L2594-2618)
```rust
    fn update_epoch_stakes(
        &mut self,
        leader_schedule_epoch: Epoch,
        prefiltered_distribution_vote_accounts: Option<VoteAccounts>,
    ) {
        // update epoch_stakes cache
        //  if my parent didn't populate for this staker's epoch, we've
        //  crossed a boundary
        if !self.epoch_stakes.contains_key(&leader_schedule_epoch) {
            self.epoch_stakes.retain(|&epoch, _| {
                // Note the greater-than-or-equal (and the `- 1`) is needed here
                // to ensure we retain the oldest epoch, if that epoch is 0.
                epoch >= leader_schedule_epoch.saturating_sub(MAX_LEADER_SCHEDULE_STAKES - 1)
            });
            // At the epoch boundary, `compute_new_epoch_caches_and_rewards`
            // has already produced the VAT-filtered vote-account snapshot;
            // reuse it here instead of re-cloning and re-filtering the
            // `stakes_cache`. Other callers (same-epoch refresh, warps)
            // fall back to `get_top_epoch_stakes`.
            let stakes = match prefiltered_distribution_vote_accounts {
                Some(prefiltered) => Stakes::new(prefiltered, self.epoch()),
                None => self.get_top_epoch_stakes(),
            };
            let stakes = SerdeStakesToStakeFormat::from(stakes);
            let new_epoch_stakes = VersionedEpochStakes::new(stakes, leader_schedule_epoch);
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L636-724)
```rust
        let CachedVoteAccounts {
            snapshot_epoch_vote_accounts,
            rewarded_epoch_vote_accounts,
            distribution_epoch_vote_accounts,
        } = cached_vote_accounts;

        let vote_pubkey = stake_account.delegation().voter_pubkey;

        let current_lamports = stake_account.lamports();
        let minimum_lamports = self
            .rent_collector
            .rent
            .minimum_balance(stake_account.data_len());
        let stake = *stake_account.stake();

        let Some(vote_account) = distribution_epoch_vote_accounts.get(&vote_pubkey) else {
            debug!("could not find vote account {vote_pubkey} in cache");
            // Even if the vote account doesn't exist, there might still be a
            // need to adjust the stake delegation
            if adjust_delegations_for_rent {
                let status = delegation_activation_status(
                    &stake.delegation,
                    rewarded_epoch,
                    stake_history,
                    new_rate_activation_epoch,
                    use_fixed_point_stake_math,
                );
                if delegation_may_need_adjustment(
                    stake.delegation.stake,
                    stake.delegation.stake,
                    current_lamports,
                    minimum_lamports,
                    status,
                ) {
                    debug!(
                        "delegation for stake {stake_pubkey} may be adjusted at distribution, \
                         unless lamports are transferred before distribution block"
                    );
                    let inflation = InflationReward {
                        stake,
                        stake_reward: 0,
                        commission_bps: (!custom_commission_collector).then_some(0),
                    };
                    // Set `is_vote_account` to `false` in order to deliberately
                    // fail during commission collector checks. This avoids
                    // creating a reward entry during payout.
                    let reward_commission = RewardCommission {
                        commission_bps: (!custom_commission_collector).then_some(0),
                        commission_lamports: 0,
                        burned_lamports: 0,
                        is_vote_account: false,
                    };
                    return Some(InflationRewardWithCommission {
                        inflation,
                        commission_pubkey: vote_pubkey,
                        reward_commission,
                    });
                } else {
                    debug!("delegation for stake {stake_pubkey} will not be adjusted");
                    return None;
                }
            } else {
                return None;
            }
        };
        let vote_state = vote_account.vote_state_view();

        // Fetch the voter commission from past epochs to attempt to
        // delay the effect of commission updates by at least one
        // full epoch.
        // When `commission_rate_in_basis_points` is true, use the new field
        // `inflation_rewards_commission_bps`; otherwise use the legacy
        // percentage field and convert to basis points by multiplying by 100.
        let commission_bps = if delay_commission_updates {
            let vote_state_for_commission = snapshot_epoch_vote_accounts
                .and_then(|eva| eva.get(&vote_pubkey))
                .or_else(|| rewarded_epoch_vote_accounts.and_then(|eva| eva.get(&vote_pubkey)))
                .map(|vote_account| vote_account.vote_state_view())
                .unwrap_or(vote_state);
            if commission_rate_in_basis_points {
                vote_state_for_commission.inflation_rewards_commission()
            } else {
                vote_state_for_commission.commission() as u16 * 100
            }
        } else if commission_rate_in_basis_points {
            vote_state.inflation_rewards_commission()
        } else {
            vote_state.commission() as u16 * 100
        };
```
