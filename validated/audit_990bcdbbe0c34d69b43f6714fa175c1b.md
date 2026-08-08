[1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** runtime/src/bank.rs (L1783-1792)
```rust
        let filtered_distribution_vote_accounts = unfiltered_distribution_vote_accounts
            .clone_and_filter_for_vat(
                MAX_ALPENGLOW_VOTE_ACCOUNTS,
                self.minimum_vote_account_balance_for_vat(),
            );
        if AlpenglowEpochType::is_alpenglow_or_migration_epoch(self, rewarded_epoch) {
            reward_epoch_delegated_stakes.set(self, &filtered_distribution_vote_accounts);
        }
        let cached_vote_accounts =
            self.get_cached_vote_accounts(rewarded_epoch, &filtered_distribution_vote_accounts);
```

**File:** runtime/src/bank.rs (L1848-1860)
```rust
        self.stakes_cache.activate_epoch(
            epoch,
            stake_history,
            unfiltered_distribution_vote_accounts,
            delegated_stakes,
        );

        // Save a snapshot of stakes for use in consensus and stake weighted networking
        let leader_schedule_epoch = self.epoch_schedule.get_leader_schedule_epoch(slot);
        let (_, update_epoch_stakes_time_us) = measure_us!(self.update_epoch_stakes(
            leader_schedule_epoch,
            Some(filtered_distribution_vote_accounts),
        ));
```

**File:** runtime/src/bank.rs (L5794-5799)
```rust
    /// current vote accounts for this bank along with the stake
    ///   attributed to each account
    pub fn vote_accounts(&self) -> Arc<VoteAccountsHashMap> {
        let stakes = self.stakes_cache.stakes();
        Arc::from(stakes.vote_accounts())
    }
```

**File:** core/src/consensus.rs (L425-437)
```rust
        let total_votes = vote_accounts
            .values()
            .filter(|(voted_stake, _)| *voted_stake != 0)
            .map(|(_, account)| account.vote_state_view().votes_len())
            .sum();
        // Flat list of intervals of lockouts of the form {voter, start, end}.
        let mut lockout_intervals = LockoutIntervals::with_capacity(total_votes);
        let mut my_latest_landed_vote = None;
        for (&key, (voted_stake, account)) in vote_accounts.iter() {
            let voted_stake = *voted_stake;
            if voted_stake == 0 {
                continue;
            }
```
