### Title
Recalculated partitioned stake rewards use the live `StakesCache` instead of an epoch-boundary snapshot, letting an attacker's post-boundary delegation changes distort their own unpaid reward relative to the epoch's fixed `total_rewards`/`total_points` - (File: `runtime/src/bank/partitioned_epoch_rewards/calculation.rs`)

### Summary
`Bank::recalculate_stake_rewards` re-derives `stake_delegations` from `self.stakes_cache.stakes()` — the bank's current, live stake state — rather than from a snapshot of delegations as they existed at the epoch boundary when `total_rewards`/`total_points` were fixed into the `EpochRewards` sysvar. Only the Alpenglow total-stake denominator (`RewardEpochDelegatedStakes`) is explicitly cached/frozen to avoid recalculation drift; the per-account delegation amount used as the numerator in both Tower and Alpenglow point math is not.

### Finding Description
`recalculate_partitioned_rewards_if_active` reads the already-fixed `PointValue { rewards: total_rewards, points: total_points }` straight from the immutable `EpochRewards` sysvar [1](#0-0) , then calls `get_epoch_params_for_recalculation`, which builds `stake_delegations` from `stakes.stake_delegations_vec()` where `stakes` is `self.stakes_cache.stakes()` of the *current* bank, not a frozen copy from the epoch-boundary block [2](#0-1) .

Point calculation for a given stake account (`tower_epoch_credits_iter` / `calculate_alpenglow_points`) multiplies `earned_credits` (fixed by the vote account's frozen epoch-credit record for the rewarded epoch) by `delegation_effective_stake(&stake.delegation, epoch, stake_history, ...)`, which is driven by `stake.delegation.stake` and `stake.delegation.activation_epoch` as they exist *at recalculation time* [3](#0-2) . Reward is then `earned_points * point_value.rewards / point_value.points`, dividing by the epoch-fixed `total_points` denominator.

An unprivileged staker who has not yet been paid in the current partitioned distribution can, on ordinary subsequent blocks of the new epoch (after `begin_partitioned_rewards` committed `total_rewards`/`total_points` but before their partition is distributed), issue normal `Merge`/`Split`/`Delegate` stake instructions on their own accounts to change `stake.delegation.stake`/`activation_epoch`. If a validator subsequently restarts and reloads from a snapshot taken after those mutations, `initialize_after_snapshot_restore` calls `recalculate_partitioned_rewards_if_active` → `recalculate_stake_rewards`, which recomputes that account's points/reward using the *mutated* delegation state while still dividing by the original, now-stale `total_points` [4](#0-3) . This can produce a `stake_reward` for that account materially different from the value fixed in the original in-memory `all_stake_rewards` at epoch boundary, breaking the invariant that individually-computed stake rewards must sum to no more than `total_rewards`.

The codebase already recognizes and mitigates exactly this class of drift for the Alpenglow *denominator* (`reward_epoch_delegated_stakes` is captured once and reused across recalculation, verified by `test_recalculate_alpenglow_rewards_after_partial_distribution_uses_original_denominator` [5](#0-4) ), but there is no equivalent protection for the numerator (`stake.delegation`) read from the live `stakes_cache`.

### Impact Explanation
If reachable, this allows an unpaid staker to alter their own final stake-reward payout after the reward pool total has already been fixed, causing the sum of distributed stake rewards for the epoch to diverge from (potentially exceed) `epoch_rewards_sysvar.total_rewards` — a violation of the value-conservation invariant for the fixed epoch inflation pool. This maps to the "misattributed/duplicated rewards" / inflation-supply-invariant category, since it can result in minting more stake rewards than the epoch's committed pool allows.

### Likelihood Explanation
The precondition — an unprivileged attacker mutating their own not-yet-distributed stake delegation between epoch-boundary calculation and a recalculation event — is directly attacker-reachable via ordinary stake instructions. However, the recalculation itself (`recalculate_partitioned_rewards_if_active`) is only invoked in this codebase from `initialize_after_snapshot_restore`, i.e., it fires only when a validator loads a snapshot mid-`EpochRewards`-distribution, which is an operational/restart event not directly triggerable by the attacker. This significantly reduces practical likelihood/repeatability, since it depends on a validator restarting at just the right time rather than being reliably attacker-forced. Additionally, whether a `Merge` of two already-activated accounts can retroactively make a *larger* `delegation.stake` appear "fully active" for a past epoch depends on stake activation/warmup semantics implemented in the external `solana-stake-interface` crate (`Delegation::stake_v2`/`stake_activating_and_deactivating_v2`), which is out of scope per SECURITY.md ("dependencies"). I could not fully verify within this session whether that external math permits such retroactive inflation, so the end-to-end exploitability (beyond the confirmed architectural gap of using live vs. frozen delegation state) remains unconfirmed.

### Recommendation
Snapshot the stake delegations (numerator) used for reward calculation at the epoch boundary alongside `total_rewards`/`total_points`/`reward_epoch_delegated_stakes`, and have `recalculate_stake_rewards` use that frozen snapshot rather than `self.stakes_cache.stakes()` at recalculation time, mirroring the protection already applied to `RewardEpochDelegatedStakes`.

### Proof of Concept
Extend `runtime/src/bank/partitioned_epoch_rewards/calculation.rs` test module with an invariant test analogous to `test_recalculate_alpenglow_rewards_after_partial_distribution_uses_original_denominator`, but for the numerator instead of the denominator:
```rust
#[test]
fn test_recalculate_stake_rewards_does_not_exceed_total_rewards_after_delegation_change() {
    // 1. create_reward_bank_with_specific_stakes(...) with >=2 delegations,
    //    small stake_account_stores_per_block so not all rewards are paid in one block.
    // 2. Advance to epoch boundary; capture original
    //    EpochRewardPhase::Calculation::all_stake_rewards and epoch_rewards_sysvar
    //    (total_rewards, total_points).
    // 3. Distribute exactly one partition (paid_index) via
    //    set_epoch_reward_status_distribution + distribute_partitioned_epoch_rewards,
    //    leaving unpaid_index pending.
    // 4. For the *unpaid* stake account, submit an ordinary Merge/Delegate
    //    instruction (as an unprivileged staker) increasing its
    //    delegation.stake beyond the original value used in step 2.
    // 5. Call bank.recalculate_stake_rewards(&epoch_rewards_sysvar, &thread_pool).
    // 6. Assert invariant:
    //    let total_recalculated: u64 = recalculated_stake_rewards
    //        .enumerated_rewards_iter()
    //        .map(|(_, r)| r.inflation.stake_reward)
    //        .sum();
    //    assert!(paid_reward.inflation.stake_reward + total_recalculated
    //            <= epoch_rewards_sysvar.total_rewards,
    //        "sum of stake rewards must never exceed the epoch's committed total_rewards");
}
```
Expected result if the bug is present: the assertion fails because the mutated delegation's recalculated `stake_reward` increases (using the post-mutation `delegation.stake`) while still being divided by the original, unchanged `total_points`, causing the sum to exceed `total_rewards`.

### Citations

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L580-608)
```rust
    /// Retrieves stake history and delegations for stake reward recalculation
    /// after snapshot restore.
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

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L1043-1058)
```rust
        assert!(epoch_rewards_sysvar.active);
        // If rewards are active, the rewarded epoch is always the immediately
        // preceding epoch.
        let rewarded_epoch = self.epoch().saturating_sub(1);

        let point_value = PointValue {
            rewards: epoch_rewards_sysvar.total_rewards,
            points: epoch_rewards_sysvar.total_points,
        };

        let stakes = self.stakes_cache.stakes();
        let EpochRewardCalculateParamInfo {
            stake_history,
            stake_delegations,
            cached_vote_accounts,
        } = self.get_epoch_params_for_recalculation(rewarded_epoch, &stakes);
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L2782-2797)
```rust
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

**File:** runtime/src/inflation_rewards/points.rs (L205-222)
```rust
        let (epoch, final_epoch_credits, initial_epoch_credits) = entry;
        let earned_credits = calc_earned_credits(
            stake,
            final_epoch_credits,
            initial_epoch_credits,
            &mut new_credits_observed,
        );
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

**File:** runtime/src/bank.rs (L6075-6081)
```rust
        self.compute_and_apply_features_after_snapshot_restore();
        self.stakes_cache.refresh_delegated_stakes(
            self.new_warmup_cooldown_rate_epoch(),
            self.use_fixed_point_stake_math(),
        );

        self.recalculate_partitioned_rewards_if_active(rewards_thread_pool_builder);
```
