### Title
Feature-gated switch between legacy and fixed-point stake math can desynchronize `Stakes::delegated_stakes`/`VoteAccounts` aggregates from per-delegation values, causing a deterministic panic - (File: `runtime/src/stakes.rs`)

### Summary
`Stakes<StakeAccount>` maintains a cumulative `delegated_stakes` map (and mirrors it into `VoteAccounts`) that is updated incrementally, transaction-by-transaction, rather than being fully recomputed on every stake-account touch. The exact per-delegation "effective stake" value that is added/subtracted from these aggregates depends on a boolean flag, `use_fixed_point_stake_math`, which is derived from the `upgrade_bpf_stake_program_to_v5_1` feature and can flip mid-epoch, at any slot, rather than only at an epoch boundary. This is structurally the same class of bug as the HMX report: an aggregate value is adjusted incrementally based on old math, while the same delegation's contribution is later recomputed under new math, so the amounts diverge.

### Finding Description
`Stakes::upsert_stake_delegation` performs an incremental update to the cumulative stake aggregates whenever a stake account changes: [1](#0-0) 

Both the "old" and "new" per-delegation stake values it uses to adjust the aggregate are computed via `delegation_effective_stake`, which dispatches to one of two different math implementations depending on the `use_fixed_point_stake_math` flag passed in at call time: [2](#0-1) 

This flag is derived from a runtime feature that can activate at any slot, not necessarily an epoch boundary: [3](#0-2) 

The cumulative aggregates are only ever *fully* recomputed from scratch (i.e., resynced) at epoch boundaries, via `calculate_activated_stake`, which folds over every stake delegation using the epoch's current flag value: [4](#0-3) [5](#0-4) 

Between epoch boundaries, however, every subsequent stake-account mutation only performs the incremental `sub_delegated_stake`/`add_delegated_stake` adjustment shown above, using whatever the *current* value of `use_fixed_point_stake_math` happens to be at that instant: [6](#0-5) 

Consequently, if the `upgrade_bpf_stake_program_to_v5_1` feature activates mid-epoch:
1. At the start of the epoch, `delegated_stakes` is fully rebuilt using the pre-activation (legacy) stake math for every delegation still warming up or cooling down.
2. Mid-epoch, the feature activates, flipping `use_fixed_point_stake_math` to `true`.
3. The next transaction that touches any stake account still in warmup/cooldown calls `upsert_stake_delegation`, which now computes `old_stake` using the *new* fixed-point math (`stake_v2`) rather than the legacy math (`stake`) that was originally folded into the aggregate at epoch start.
4. If the new math yields a different (e.g., larger) effective-stake value than the legacy math did for the same partially-activated/deactivated delegation, `sub_delegated_stake`'s `checked_sub(...).expect(...)` will underflow and panic: [7](#0-6) 

This mirrors the HMX pattern exactly: `_vars.globalState.reserveValueE30` (here, `delegated_stakes`) is adjusted incrementally based on a stale per-item computation, while the per-item value itself (here, `old_stake`) is recomputed under a changed set of "config parameters" (here, the stake math mode), producing a mismatch that leads to an arithmetic failure exactly analogous to the underflow HMX describes on close/liquidation — except here it manifests as a Rust `panic!` inside consensus-critical bank code rather than a Solidity revert.

### Impact Explanation
Because feature activation is deterministic and identical across all correctly-configured validators (the feature account and activation slot are consensus data), every validator that processes the triggering transaction after the feature flips will hit the same `expect()` panic at the same point in the same slot. This is a cluster-wide, deterministic crash of the validator's bank-processing path — a consensus/liveness halt triggered by ordinary stake-account activity (delegate/deactivate/redelegate) rather than by any validator or operator misbehavior, which is within the intended unprivileged-user scope (stake accounting paths).

### Likelihood Explanation
Likelihood is bounded by whether the legacy (`stake()`) and fixed-point (`stake_v2()`) math implementations can actually diverge for the same `Delegation`/epoch/`StakeHistory` input while a delegation is still activating or deactivating (i.e., not fully warmed up/cooled down). I was not able to inspect the internal `stake_v2`/`stake` implementations in the `solana-stake-interface` crate within the available context, so I cannot fully confirm the magnitude/direction of the discrepancy or the exact conditions needed to trigger an underflow versus a silent value drift. This is the main open uncertainty in this analysis, and I would want a background agent to trace `solana_stake_interface::state::Delegation::stake` vs `stake_v2`/`stake_activating_and_deactivating` vs `_v2` to confirm they can disagree on a still-warming/cooling delegation.

### Recommendation
Ensure `Stakes::delegated_stakes` (and the mirrored `VoteAccounts` stakes) are never adjusted incrementally using a stake-math mode (`use_fixed_point_stake_math`/`new_rate_activation_epoch`) that differs from the mode used when that delegation's contribution was originally folded into the aggregate. Concretely, force a full `refresh_delegated_stakes` recomputation immediately when `upgrade_bpf_stake_program_to_v5_1` (or any similar feature gating `delegation_effective_stake`) activates, before any further incremental `upsert_stake_delegation`/`remove_stake_delegation` calls are processed in that slot — mirroring how `initialize_after_snapshot_restore` already calls `refresh_delegated_stakes` after feature recomputation: [8](#0-7) 

### Proof of Concept
Not independently reproduced; derived by static code tracing of `Stakes::upsert_stake_delegation`/`sub_delegated_stake` and the feature-gated dispatch in `delegation_effective_stake`. A concrete PoC would require: (1) confirming a divergence between `Delegation::stake()` and `Delegation::stake_v2()` for a partially warmed-up/cooled-down delegation at a given `StakeHistory` epoch, and (2) constructing a scenario where `upgrade_bpf_stake_program_to_v5_1` activates mid-epoch immediately followed by a stake-modifying transaction on such a delegation, which is left for further investigation/verification by a background agent with compile/test access.

### Citations

**File:** runtime/src/stakes.rs (L434-502)
```rust
    pub(crate) fn calculate_activated_stake(
        &self,
        next_epoch: Epoch,
        thread_pool: &ThreadPool,
        new_rate_activation_epoch: Option<Epoch>,
        stake_delegations: &[(&Pubkey, &StakeAccount)],
        use_fixed_point_stake_math: bool,
    ) -> (
        StakeHistory,
        VoteAccounts,
        DelegatedStakes,
        RewardEpochDelegatedStakes,
    ) {
        // Wrap up the prev epoch by adding new stake history entry for the
        // prev epoch.
        let (stake_history_entry, effective_delegated_stakes) = thread_pool.install(|| {
            stake_delegations
                .par_iter()
                .fold(
                    || (StakeActivationStatus::default(), HashMap::default()),
                    |(acc, mut delegated_stakes), (_stake_pubkey, stake_account)| {
                        let delegation = stake_account.delegation();
                        let activation_status = delegation_activation_status(
                            delegation,
                            self.epoch,
                            &self.stake_history,
                            new_rate_activation_epoch,
                            use_fixed_point_stake_math,
                        );
                        *delegated_stakes.entry(delegation.voter_pubkey).or_default() +=
                            activation_status.effective;
                        (acc + activation_status, delegated_stakes)
                    },
                )
                .reduce(
                    || (StakeActivationStatus::default(), HashMap::default()),
                    |(activation_status_a, delegated_stakes_a),
                     (activation_status_b, delegated_stakes_b)| {
                        (
                            activation_status_a + activation_status_b,
                            merge_delegated_stakes(delegated_stakes_a, delegated_stakes_b),
                        )
                    },
                )
        });
        let mut stake_history = self.stake_history.clone();
        stake_history.add(self.epoch, stake_history_entry);
        // Refresh the stake distribution of vote accounts for the next epoch,
        // using new stake history.
        let (vote_accounts, delegated_stakes) = refresh_vote_accounts(
            thread_pool,
            next_epoch,
            &self.vote_accounts,
            stake_delegations,
            &stake_history,
            new_rate_activation_epoch,
            use_fixed_point_stake_math,
        );
        let reward_epoch_delegated_stakes = RewardEpochDelegatedStakes {
            epoch: self.epoch,
            delegated_stakes: effective_delegated_stakes,
        };
        (
            stake_history,
            vote_accounts,
            delegated_stakes,
            reward_epoch_delegated_stakes,
        )
    }
```

**File:** runtime/src/stakes.rs (L555-576)
```rust
    fn add_delegated_stake(&mut self, voter_pubkey: Pubkey, stake: u64) {
        if stake == 0 {
            return;
        }
        *self.delegated_stakes.entry(voter_pubkey).or_default() += stake;
    }

    fn sub_delegated_stake(&mut self, voter_pubkey: &Pubkey, stake: u64) {
        if stake == 0 {
            return;
        }
        let current_stake = self
            .delegated_stakes
            .get_mut(voter_pubkey)
            .expect("subtraction from missing delegated stake");
        *current_stake = current_stake
            .checked_sub(stake)
            .expect("subtraction value exceeds delegated stake");
        if *current_stake == 0 {
            self.delegated_stakes.remove(voter_pubkey);
        }
    }
```

**File:** runtime/src/stakes.rs (L620-660)
```rust
    fn upsert_stake_delegation(
        &mut self,
        stake_pubkey: Pubkey,
        stake_account: StakeAccount,
        new_rate_activation_epoch: Option<Epoch>,
        use_fixed_point_stake_math: bool,
    ) {
        debug_assert_ne!(stake_account.lamports(), 0u64);
        let delegation = stake_account.delegation();
        let voter_pubkey = delegation.voter_pubkey;
        let stake = delegation_effective_stake(
            delegation,
            self.epoch,
            &self.stake_history,
            new_rate_activation_epoch,
            use_fixed_point_stake_math,
        );
        match self.stake_delegations.insert(stake_pubkey, stake_account) {
            None => {
                self.add_delegated_stake(voter_pubkey, stake);
                self.vote_accounts.add_stake(&voter_pubkey, stake);
            }
            Some(old_stake_account) => {
                let old_delegation = old_stake_account.delegation();
                let old_voter_pubkey = old_delegation.voter_pubkey;
                let old_stake = delegation_effective_stake(
                    old_delegation,
                    self.epoch,
                    &self.stake_history,
                    new_rate_activation_epoch,
                    use_fixed_point_stake_math,
                );
                if voter_pubkey != old_voter_pubkey || stake != old_stake {
                    self.sub_delegated_stake(&old_voter_pubkey, old_stake);
                    self.add_delegated_stake(voter_pubkey, stake);
                    self.vote_accounts.sub_stake(&old_voter_pubkey, old_stake);
                    self.vote_accounts.add_stake(&voter_pubkey, stake);
                }
            }
        }
    }
```

**File:** runtime/src/stake_delegation.rs (L9-23)
```rust
#[inline]
pub(crate) fn delegation_effective_stake<T: StakeHistoryGetEntry>(
    delegation: &Delegation,
    epoch: Epoch,
    history: &T,
    new_rate_activation_epoch: Option<Epoch>,
    use_fixed_point_stake_math: bool,
) -> u64 {
    if use_fixed_point_stake_math {
        delegation.stake_v2(epoch, history, new_rate_activation_epoch)
    } else {
        #[allow(deprecated)]
        delegation.stake(epoch, history, new_rate_activation_epoch)
    }
}
```

**File:** runtime/src/bank.rs (L1717-1721)
```rust
    fn use_fixed_point_stake_math(&self) -> bool {
        self.feature_set
            .snapshot()
            .upgrade_bpf_stake_program_to_v5_1
    }
```

**File:** runtime/src/bank.rs (L1750-1778)
```rust
    /// Returns updated stake history and vote accounts that includes new
    /// activated stake from the last epoch.
    fn compute_new_epoch_caches_and_rewards(
        &self,
        thread_pool: &ThreadPool,
        rewarded_epoch: Epoch,
        reward_calc_tracer: Option<impl RewardCalcTracer>,
        rewards_metrics: &mut RewardsMetrics,
    ) -> NewEpochBundle {
        // Add new entry to stakes.stake_history, set appropriate epoch and
        // update vote accounts with warmed up stakes before saving a
        // snapshot of stakes in epoch stakes
        let stakes = self.stakes_cache.stakes();
        let stake_delegations = stakes.stake_delegations_vec();
        let (
            (
                stake_history,
                unfiltered_distribution_vote_accounts,
                delegated_stakes,
                reward_epoch_delegated_stakes,
            ),
            calculate_activated_stake_time_us,
        ) = measure_us!(stakes.calculate_activated_stake(
            self.epoch(),
            thread_pool,
            self.new_warmup_cooldown_rate_epoch(),
            &stake_delegations,
            self.use_fixed_point_stake_math(),
        ));
```

**File:** runtime/src/bank.rs (L6061-6079)
```rust
    /// Compute and apply all activated features, initialize the transaction
    /// processor, and recalculate partitioned rewards if needed
    fn initialize_after_snapshot_restore<F, TP>(&mut self, rewards_thread_pool_builder: F)
    where
        F: FnOnce() -> TP,
        TP: std::borrow::Borrow<ThreadPool>,
    {
        self.transaction_processor =
            TransactionBatchProcessor::new_uninitialized(self.slot, self.epoch);
        if let Some(compute_budget) = &self.compute_budget {
            self.transaction_processor
                .set_execution_cost(compute_budget.to_cost());
        }

        self.compute_and_apply_features_after_snapshot_restore();
        self.stakes_cache.refresh_delegated_stakes(
            self.new_warmup_cooldown_rate_epoch(),
            self.use_fixed_point_stake_math(),
        );
```
