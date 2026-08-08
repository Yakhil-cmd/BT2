### Title
Stake-reward recalculation on snapshot-restore reads live (attacker-mutable) delegation amounts instead of the epoch-boundary snapshot, causing reward-state divergence between restarted and non-restarted validators - (File: `runtime/src/bank/partitioned_epoch_rewards/calculation.rs`)

### Summary
`Bank::recalculate_stake_rewards`, invoked from `Bank::initialize_after_snapshot_restore` after a validator restart, recomputes every pending `PartitionedStakeReward` using the *live* `StakesCache` (`stakes.stake_delegations_vec()`) rather than the delegation amounts that existed when the epoch-boundary calculation ran. Because `Delegation::stake` is a single mutable field with no historical snapshot, any stake instruction (e.g. `Split`) that changes an already-rewarded account's `delegation.stake` between epoch-boundary calculation and a peer's restart causes that peer to compute a different `PartitionedStakeReward` (and thus different lamports/`Stake` state to be stored at the deterministic future distribution block) than validators that never restarted and are still using the originally cached `all_stake_rewards`.

### Finding Description
`recalculate_stake_rewards` is only reached via `initialize_after_snapshot_restore` -> `recalculate_partitioned_rewards_if_active`, which is called on every snapshot-restored/restarted `Bank` while `EpochRewards` is still active: [1](#0-0) [2](#0-1) 

Inside it, the stake data used for recalculation is pulled straight from the current in-memory `StakesCache`, not from any epoch-boundary snapshot: [3](#0-2) [4](#0-3) 

The function's own comment acknowledges this exact class of bug for `RewardCommissionAccounts` ("the commission account is loaded from the current bank, and not the start of the epoch... For this reason, the `RewardCommissionAccounts` calculated in this function call should NOT be used ever"), but the fix implemented in the codebase (`RewardEpochDelegatedStakes`, an off-curve account snapshotting *total* delegated stake per vote account) only freezes the **denominator** used in `calculate_alpenglow_points`: [5](#0-4) 

The **numerator** — each staker's own effective stake — is still derived from the live, mutable `Delegation::stake` field via `delegation_effective_stake`, with no analogous historical snapshot: [6](#0-5) [7](#0-6) [8](#0-7) 

An unprivileged attacker can send a `Split` instruction against their own already-reward-eligible stake account during the `Calculation`/`Distribution` window; this deterministically decreases `delegation.stake` for that account in the live `StakesCache` for every node that processes the block, before any restart occurs. If a validator subsequently restarts and calls `initialize_after_snapshot_restore`, `recalculate_stake_rewards` recomputes that account's stake reward from the *reduced* current delegation, replacing the entire `PartitionedStakeRewards`/`all_stake_rewards` list via `set_epoch_reward_status_distribution`. Non-restarted peers keep the original, unmodified `all_stake_rewards` computed with the pre-Split delegation amount. Both sets are later applied deterministically per block height in `distribute_epoch_rewards_in_partition` / `build_updated_stake_reward`, so the two classes of validators mint/credit different lamport amounts and write different `Stake` state for the same account at the same slot — a bank-hash divergence.

The existing regression test `test_recalculate_alpenglow_rewards_after_partial_distribution_uses_original_denominator` demonstrates the authors are aware of and test for exactly this class of consistency requirement, but only for the AG total-stake denominator, not for an individual account's own delegation amount changing via ordinary Stake-program instructions: [9](#0-8) 

### Impact Explanation
This is a cross-node state-divergence bug: honest validators that restart mid-`EpochRewards` window compute and later store different lamport credits / `Stake` account contents than honest validators that do not restart, for the same block sequence and the same attacker-controlled account. This violates the required invariant that all honest nodes reach identical bank state for identical blocks, and manifests as a bank-hash mismatch — leading to consensus failure/partial chain halt for the fraction of the cluster that happened to restart during the reward-distribution window. This falls into the "stake, epoch-stakes, leader-schedule, and reward state divergence" / consensus-halt category.

### Likelihood Explanation
Preconditions are entirely within attacker control except the restart itself: the attacker only needs an existing delegated stake account that is included in the current epoch's reward set, and to submit an ordinary `Split` (or similar delegation-reducing) instruction during the `Calculation`/`Distribution` window, which any unprivileged staker can always do. Validator restarts (process crash/restart, forced snapshot reload, operator maintenance) happen routinely and are not attacker-controlled but also not rare; the attacker merely needs to time their own transaction to land within the multi-block reward-distribution window (which spans many blocks by design) and wait — this requires no coordination with any validator operator. Given that any restart-and-recalculate event within that window against a mutated account triggers the divergence, this is realistically and repeatably triggerable.

### Recommendation
`recalculate_stake_rewards` must not use the live `StakesCache` to reconstruct amounts that are supposed to be frozen at the epoch boundary. Instead, capture and persist (e.g., in a scheme parallel to `RewardEpochDelegatedStakesAccount`) the actual `all_stake_rewards`/`PartitionedStakeRewards` (or the delegation snapshot needed to reproduce it) computed at calculation time, and on snapshot restore, restore that exact serialized value instead of recomputing from current state. If recomputation must be kept as a fallback, it should snapshot every stake delegation amount used in the epoch-boundary calculation the same way `RewardEpochDelegatedStakes` snapshots vote-account totals, not just the total-stake denominator.

### Proof of Concept
Extend `test_recalculate_stake_rewards` (or `test_recalculate_alpenglow_rewards_after_partial_distribution_uses_original_denominator`) in `runtime/src/bank/partitioned_epoch_rewards/calculation.rs`:
1. Build a reward bank as in `test_recalculate_stake_rewards`, reach the epoch boundary so `EpochRewardStatus::Active(EpochRewardPhase::Calculation(status))` is populated with `all_stake_rewards` for a known `stake_pubkey`.
2. Before calling `recalculate_stake_rewards`, simulate a `Split` by directly mutating the stake account for `stake_pubkey` in the bank's stakes cache/accounts-db: reduce `delegation.stake` by some amount `d` and store the resulting reduced account (representing a legitimate `Split` transaction having been processed by a block in between).
3. Call `bank.recalculate_stake_rewards(&epoch_rewards_sysvar, &thread_pool)` and compare the resulting `PartitionedStakeReward` for `stake_pubkey` against the original one cached in `calculation_status.all_stake_rewards` before the mutation.
4. Assert (expected to fail, proving the bug): `recalculated_reward.inflation.stake_reward == original_reward.inflation.stake_reward` and `recalculated_reward.inflation.stake.delegation.stake == original_reward.inflation.stake.delegation.stake`. The test should show these differ by an amount proportional to `d`, demonstrating that a restarted validator and a non-restarted validator would apply different lamport credits/`Stake` state to the same account at the same future distribution block height, producing different bank hashes.

### Citations

**File:** runtime/src/bank.rs (L6075-6081)
```rust
        self.compute_and_apply_features_after_snapshot_restore();
        self.stakes_cache.refresh_delegated_stakes(
            self.new_warmup_cooldown_rate_epoch(),
            self.use_fixed_point_stake_math(),
        );

        self.recalculate_partitioned_rewards_if_active(rewards_thread_pool_builder);
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L582-608)
```rust
    fn get_epoch_params_for_recalculation<'a>(
        &'a self,
        rewarded_epoch: Epoch,
        stakes: &'a Stakes<StakeAccount<Delegation>>,
    ) -> EpochRewardCalculateParamInfo<'a> {
        // Use `stakes` for stake-related info
        let stake_history = stakes.history().clone();
        let stake_delegations = stakes.stake_delegations_vec();

        // Use the VAT-filtered vote-account snapshot from epoch_stakes.
        // Recalculation should match the vote-account admission policy used for
        // distribution.
        let leader_schedule_epoch = self.epoch_schedule().get_leader_schedule_epoch(self.slot());
        let distribution_epoch_vote_accounts = self
            .epoch_stakes(leader_schedule_epoch)
            .expect("calculation should always run after Bank::update_epoch_stakes()")
            .stakes()
            .vote_accounts();
        let cached_vote_accounts =
            self.get_cached_vote_accounts(rewarded_epoch, distribution_epoch_vote_accounts);

        EpochRewardCalculateParamInfo {
            stake_history,
            stake_delegations,
            cached_vote_accounts,
        }
    }
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L1015-1032)
```rust
    pub(in crate::bank) fn recalculate_partitioned_rewards_if_active<F, TP>(
        &mut self,
        thread_pool_builder: F,
    ) where
        F: FnOnce() -> TP,
        TP: std::borrow::Borrow<ThreadPool>,
    {
        let epoch_rewards_sysvar = self.get_epoch_rewards_sysvar();
        if epoch_rewards_sysvar.active {
            let thread_pool = thread_pool_builder();
            let (stake_rewards, partition_indices) =
                self.recalculate_stake_rewards(&epoch_rewards_sysvar, thread_pool.borrow());
            self.set_epoch_reward_status_distribution(
                epoch_rewards_sysvar.distribution_starting_block_height,
                stake_rewards,
                partition_indices,
            );
        }
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L1053-1088)
```rust
        let stakes = self.stakes_cache.stakes();
        let EpochRewardCalculateParamInfo {
            stake_history,
            stake_delegations,
            cached_vote_accounts,
        } = self.get_epoch_params_for_recalculation(rewarded_epoch, &stakes);
        let ag_epoch_type = AlpenglowEpochType::get(self, rewarded_epoch, || {
            RewardEpochDelegatedStakes::get(self)
        });

        // On recalculation, only the `StakeRewardCalculation::stake_rewards`
        // field is relevant. It is assumed that reward commission accounts have
        // already been calculated and delivered, while
        // `StakeRewardCalculation::total_rewards` only reflects rewards that
        // have not yet been distributed.
        //
        // NOTE: the `RewardCommissionAccounts` will NOT have a correct
        // post_lamport amount if the commission account is NOT the vote account,
        // because the commission account is loaded from the current bank, and
        // not the start of the epoch. We don't have a snapshot of all commission
        // accounts from the start of the epoch. For this reason, the
        // `RewardCommissionAccounts` calculated in this function call should
        // NOT be used ever.
        let (_, StakeRewardCalculation { stake_rewards, .. }) = self
            .calculate_stake_rewards_and_commissions(
                &stake_history,
                stake_delegations,
                cached_vote_accounts,
                rewarded_epoch,
                point_value,
                &ag_epoch_type,
                thread_pool,
                null_tracer(),
                &mut RewardsMetrics::default(), // This is required, but not reporting anything at the moment
            );
        drop(stakes);
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L2772-2797)
```rust
        // Force exactly one stake reward to be distributed before simulating
        // snapshot restore. That write updates StakesCache with a larger
        // delegation for the same vote account.
        bank.set_epoch_reward_status_distribution(
            bank.block_height(),
            Arc::clone(&original_stake_rewards),
            vec![vec![paid_index], vec![unpaid_index]],
        );
        bank.distribute_partitioned_epoch_rewards();

        let epoch_rewards_sysvar = bank.get_epoch_rewards_sysvar();
        assert!(epoch_rewards_sysvar.active);
        let (recalculated_stake_rewards, _partition_indices) =
            bank.recalculate_stake_rewards(&epoch_rewards_sysvar, &thread_pool);
        let recalculated_unpaid_reward = recalculated_stake_rewards
            .enumerated_rewards_iter()
            .find_map(|(_index, reward)| {
                (reward.stake_pubkey == unpaid_reward.stake_pubkey).then_some(reward)
            })
            .expect("unpaid stake reward must still be pending after recalculation");

        assert_eq!(
            unpaid_reward.inflation.stake_reward, recalculated_unpaid_reward.inflation.stake_reward,
            "recalculation after partial distribution must use the same AG delegated stake \
             denominator as the original epoch-boundary calculation"
        );
```

**File:** runtime/src/inflation_rewards/points.rs (L212-222)
```rust
        let stake_amount = u128::from(delegation_effective_stake(
            &stake.delegation,
            epoch,
            stake_history,
            new_rate_activation_epoch,
            use_fixed_point_stake_math,
        ));

        // finally calculate points for this epoch
        let earned_points = stake_amount * earned_credits;
        points += earned_points;
```

**File:** runtime/src/inflation_rewards/points.rs (L272-278)
```rust
    let stake_amount = u128::from(delegation_effective_stake(
        &stake.delegation,
        epoch,
        stake_history,
        new_rate_activation_epoch,
        use_fixed_point_stake_math,
    ));
```

**File:** runtime/src/inflation_rewards/points.rs (L280-301)
```rust
    let earned_points = if earned_credits == 0 || stake_amount == 0 {
        0
    } else {
        let Some(total_stake) = reward_epoch_delegated_stakes
            .delegated_stakes
            .get(&stake.delegation.voter_pubkey)
            .copied()
            .filter(|stake| *stake != 0)
        else {
            record_error(format!(
                "AG delegated stake denominator for vote_pubkey={} in epoch={} failed",
                stake.delegation.voter_pubkey, reward_epoch_delegated_stakes.epoch
            ));
            return Err(CalculatedStakePoints {
                tower_points: 0,
                ag_points: 0,
                new_credits_observed,
                force_credits_update_with_skipped_reward: true,
            });
        };
        earned_credits * stake_amount / total_stake as u128
    };
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
