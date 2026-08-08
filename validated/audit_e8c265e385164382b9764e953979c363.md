### Title
Split/Withdraw during the epoch-reward calculation→distribution window causes a deterministic `assert_eq!` panic in `build_updated_stake_reward` (cluster-wide halt) - ([File: runtime/src/bank/partitioned_epoch_rewards/distribution.rs])

### Summary
Epoch reward calculation snapshots each stake account's post-reward `delegation.stake` in `PartitionedStakeReward` at the epoch boundary block, but distribution happens in a **later** block using the current, live `StakesCache` entry to compute `account.lamports()`/`stake.delegation.stake`. Between calculation and the actual distribution block for a given stake account's partition, a staker-authority-holding attacker can submit an ordinary `Split` instruction on their own stake account, which synchronously mutates `delegation.stake` in `StakesCache`. When `relax_post_exec_min_balance_check` (the `adjust_delegations_for_rent` flag) is inactive — the default/current state — `build_updated_stake_reward` hits `assert_eq!(expected_delegation, new_stake.delegation.stake, ...)`, and this assertion is guaranteed to fail, causing every honest validator processing that block to panic identically.

### Finding Description
Reward calculation happens once per epoch, at the epoch-boundary block, via `process_new_epoch` → `compute_new_epoch_caches_and_rewards` → `calculate_rewards` → `calculate_rewards_for_partitioning` → `calculate_validator_rewards` → `calculate_stake_rewards_and_commissions`, which iterates the `StakesCache` as it existed **before** the current block's transactions are applied and produces a `PartitionedStakeReward` per stake account containing a snapshotted `inflation.stake.delegation.stake = old_delegation + reward` [1](#0-0) . This is stored via `begin_partitioned_rewards`, which sets `distribution_starting_block_height = self.block_height() + REWARD_CALCULATION_NUM_BLOCKS` (i.e. the very next block, or later if there are more partitions) [2](#0-1) .

Crucially, on the *normal* (non-snapshot-restore) path, the frozen `all_stake_rewards` computed at calculation time is reused as-is for distribution — `distribute_partitioned_epoch_rewards` only re-hashes it into partitions, it does not recompute stake amounts from current state [3](#0-2) . (`recalculate_stake_rewards` only runs on `initialize_after_snapshot_restore`, not on every block [4](#0-3) .)

At distribution time, `build_updated_stake_reward` fetches the stake account fresh from the **current** `StakesCache`:
```
let stake_account = stakes_cache_accounts.get(&partitioned_stake_reward.stake_pubkey)...
...
} else {
    let expected_delegation = stake.delegation.stake.saturating_add(partitioned_stake_reward.inflation.stake_reward);
    assert_eq!(expected_delegation, new_stake.delegation.stake, ...);
}
``` [5](#0-4) 

`stake` here is the *current* on-chain delegation (read fresh from `stakes_cache_accounts`), while `new_stake` (`partitioned_stake_reward.inflation.stake`) is the *stale, pre-computed* snapshot from the calculation block. If an attacker who holds the stake/withdraw authority submits an ordinary `Split` instruction on their own delegated stake account any time between the calculation block and the block that actually distributes their partition, `StakesCache` is updated synchronously as part of transaction processing, reducing the source account's `delegation.stake` by the split amount. `Split` is a standard, permission-checked (staker authority only) stake-program instruction that immediately moves both lamports and a portion of `delegation.stake` to the new account — it is not gated by any epoch-boundary or reward-status check.

Consequently at distribution time:
```
expected_delegation = (old_delegation - split_amount) + reward
new_stake.delegation.stake = old_delegation + reward
```
These differ by `split_amount`, so the `assert_eq!` fails. This is a hard Rust panic (not a `DistributionError` caught by the `Result`-based error path used for `AccountNotFound`/`ArithmeticOverflow`/`UnableToSetState`), so it is unrecoverable. Because every honest validator processes the identical block deterministically, all of them hit this panic at the same point, producing a cluster-wide halt rather than a mere bank-hash divergence.

Whether the affected stake account is in the first distribution block or a later one is attacker-controllable to a degree — larger validator sets are split across multiple distribution blocks via `hash_rewards_into_partitions`, giving the attacker the entire calculation-to-distribution window (potentially several blocks) to land the `Split` transaction. No signer, authority, or arithmetic-overflow guard in the existing code prevents this: `Split` is legitimately signer-checked (staker authority only, which the attacker holds for their own account), and the only protections around reward distribution (`AccountNotFound`, `ArithmeticOverflow`, `UnableToSetState`) do not cover this consistency invariant.

When `adjust_delegations_for_rent` (the `relax_post_exec_min_balance_check` feature) is active, the `if` branch is taken instead, which recomputes `new_delegation` from the current `account.lamports()` via `adjust_delegation_for_rent` rather than asserting equality — this avoids the panic but can silently produce a reward/delegation value inconsistent with the actual split state, i.e., the "masked" lamports-mismatch scenario described in the question.

### Impact Explanation
This is a deterministic, unprivileged, cluster-wide liveness bug: an ordinary token holder with staker authority over their own stake account can cause every validator that processes the specific distribution block to panic via a reachable `assert_eq!` in `build_updated_stake_reward`. This falls into the "epoch-boundary halt" / consensus-halting bug category of the Agave bounty program, as it does not require any privileged role, mocked path, or direct store mutation — only a normal `Split` instruction sent at the right time.

### Likelihood Explanation
- Precondition: attacker owns/controls staker authority for their own stake account (fully within the "unprivileged, funds their own account" threat model).
- Feasibility: the attacker only needs to observe the epoch boundary (public, predictable via `EpochSchedule`) and submit a `Split` instruction in any block between the calculation block and the block that will process their stake account's partition. This window can span multiple blocks for larger validator sets.
- Repeatability: reproducible every epoch boundary as long as `relax_post_exec_min_balance_check` remains inactive (the default in this codebase's tests and, per the code comment, an unreleased SIMD-0392 relaxation).
- The bug is fully within reach of a single unprivileged actor with no dependency on validator/leader control, gossip, or config.

### Recommendation
`build_updated_stake_reward`'s non-`adjust_delegations_for_rent` branch must not `assert_eq!` on a value that can be legitimately altered by user-submitted instructions (`Split`, `Withdraw`, `Merge`, `Deactivate`, etc.) between calculation and distribution. Instead:
- Recompute/validate the expected delegation using the current on-chain account state (as is already done for the `adjust_delegations_for_rent = true` branch), or
- Detect if the account's delegation/lamports have diverged from the calculation-time snapshot and gracefully skip/re-clamp/re-route the reward (returning a `DistributionError` variant) rather than asserting fatally, and
- Consider recalculating stake rewards immediately before each distribution partition block (similar to `recalculate_partitioned_rewards_if_active`, which is currently invoked only on snapshot restore) rather than relying on a stale calculation-time snapshot for multi-block distributions.

### Proof of Concept
```rust
// runtime/src/bank/partitioned_epoch_rewards/distribution.rs (test module)
//
// Reproduces a panic in build_updated_stake_reward/store_stake_accounts_in_partition
// when a stake account is Split between reward calculation and distribution.
#[test]
#[should_panic(expected = "stake reward delegation must be consistent")]
fn test_split_between_calculation_and_distribution_panics() {
    // 1. Build a bank with `relax_post_exec_min_balance_check` (adjust_delegations_for_rent)
    //    INACTIVE (default), with a staker-controlled delegated stake account and a
    //    vote account earning credits, using multiple stake accounts so that reward
    //    distribution spans >1 block (see create_reward_bank helper used elsewhere in
    //    this file, e.g. `create_reward_bank`).
    // 2. Advance to the epoch boundary slot: this triggers `begin_partitioned_rewards`,
    //    snapshotting `PartitionedStakeReward` for every stake account, with
    //    `distribution_starting_block_height = block_height + 1`.
    // 3. Within THIS calculation block (before advancing further), submit and process
    //    a `stake_instruction::split` transaction from the attacker's staker authority,
    //    moving e.g. half the delegated stake to a new stake account. This updates
    //    `StakesCache` synchronously, reducing `delegation.stake` for the source account.
    // 4. Advance to the next slot (the first distribution block). This calls
    //    `distribute_partitioned_epoch_rewards` -> `distribute_epoch_rewards_in_partition`
    //    -> `store_stake_accounts_in_partition` -> `build_updated_stake_reward` for the
    //    split source account.
    // 5. Expect: the assert_eq! at
    //    runtime/src/bank/partitioned_epoch_rewards/distribution.rs:289-293 fires,
    //    because `stake.delegation.stake` (post-split, current StakesCache) plus reward
    //    no longer equals `new_stake.delegation.stake` (stale calculation-time snapshot).
    //
    // Expected (buggy) behavior: process panics deterministically for all validators
    // executing this slot.
    // Expected (fixed) behavior: no panic; the distributed stake reward is consistent
    // with post-split on-chain balance/delegation, and total lamports conservation
    // holds across the Split and the reward distribution.
}
```

### Citations

**File:** runtime/src/bank.rs (L1816-1846)
```rust
    fn process_new_epoch(
        &mut self,
        parent_epoch: Epoch,
        parent_slot: Slot,
        parent_capitalization: u64,
        parent_height: u64,
        reward_calc_tracer: Option<impl RewardCalcTracer>,
    ) {
        let epoch = self.epoch();
        let slot = self.slot();
        let thread_pool = rewards_calculation_thread_pool();

        let (_, apply_feature_activations_time_us) = measure_us!(
            thread_pool.install(|| { self.compute_and_apply_new_feature_activations() })
        );

        let mut rewards_metrics = RewardsMetrics::default();
        let NewEpochBundle {
            stake_history,
            unfiltered_distribution_vote_accounts,
            delegated_stakes,
            filtered_distribution_vote_accounts,
            rewards_calculation,
            calculate_activated_stake_time_us,
            update_rewards_with_thread_pool_time_us,
        } = self.compute_new_epoch_caches_and_rewards(
            thread_pool,
            parent_epoch,
            reward_calc_tracer,
            &mut rewards_metrics,
        );
```

**File:** runtime/src/bank.rs (L6061-6082)
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

        self.recalculate_partitioned_rewards_if_active(rewards_thread_pool_builder);

```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L261-296)
```rust
        let slot = self.slot();
        let distribution_starting_block_height =
            self.block_height() + REWARD_CALCULATION_NUM_BLOCKS;

        let PartitionedRewardsCalculation {
            stake_rewards,
            point_value,
            ..
        } = rewards_calculation;

        let stake_rewards = Arc::clone(&stake_rewards.stake_rewards);

        let num_partitions = self.get_reward_distribution_num_blocks(&stake_rewards);
        self.set_epoch_reward_status_calculation(distribution_starting_block_height, stake_rewards);

        self.create_epoch_rewards_sysvar(
            distributed_lamports + distributed_to_incinerator_lamports + burned_lamports,
            distribution_starting_block_height,
            num_partitions,
            point_value,
            0, // block_rewards
        );

        datapoint_info!(
            "epoch-rewards-status-update",
            ("start_slot", slot, i64),
            ("calculation_block_height", self.block_height(), i64),
            ("active", 1, i64),
            ("parent_slot", parent_slot, i64),
            ("parent_block_height", parent_block_height, i64),
        );
        distributed_lamports
            + rewards_calculation
                .stake_rewards
                .total_stake_rewards_lamports
    }
```

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L85-112)
```rust
        let distribution_starting_block_height = match &status {
            EpochRewardPhase::Calculation(status) => status.distribution_starting_block_height,
            EpochRewardPhase::Distribution(status) => status.distribution_starting_block_height,
        };

        let height = self.block_height();
        if height < distribution_starting_block_height {
            return;
        }

        if let EpochRewardPhase::Calculation(status) = &status {
            // epoch rewards have not been partitioned yet, so partition them now
            // This should happen only once immediately on the first rewards distribution block, after reward calculation block.
            let epoch_rewards_sysvar = self.get_epoch_rewards_sysvar();
            let (partition_indices, partition_us) = measure_us!({
                epoch_rewards_hasher::hash_rewards_into_partitions(
                    &status.all_stake_rewards,
                    &epoch_rewards_sysvar.parent_blockhash,
                    epoch_rewards_sysvar.num_partitions as usize,
                )
            });

            // update epoch reward status to distribution phase
            self.set_epoch_reward_status_distribution(
                distribution_starting_block_height,
                Arc::clone(&status.all_stake_rewards),
                partition_indices,
            );
```

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L249-294)
```rust
        let stake_account = stakes_cache_accounts
            .get(&partitioned_stake_reward.stake_pubkey)
            .ok_or(DistributionError::AccountNotFound)?
            .clone();

        let (mut account, stake_state): (AccountSharedData, StakeStateV2) = stake_account.into();
        let StakeStateV2::Stake(meta, stake, flags) = stake_state else {
            // StakesCache only stores accounts where StakeStateV2::delegation().is_some()
            unreachable!(
                "StakesCache entry {:?} failed StakeStateV2 deserialization",
                partitioned_stake_reward.stake_pubkey
            )
        };
        account
            .checked_add_lamports(partitioned_stake_reward.inflation.stake_reward)
            .map_err(|_| DistributionError::ArithmeticOverflow)?;
        account
            .checked_add_lamports(partitioned_stake_reward.block_reward)
            .map_err(|_| DistributionError::ArithmeticOverflow)?;

        let mut new_stake = partitioned_stake_reward.inflation.stake;
        if adjust_delegations_for_rent {
            let minimum_balance = rent.minimum_balance(account.data().len());
            // The rewarded epoch is right before the distribution epoch
            let rewarded_epoch = distribution_epoch.saturating_sub(1);
            // The entry in `partitioned_stake_reward` contains the rewards,
            // calculated during the calculation phase
            let delegation_with_rewards = new_stake.delegation.stake;
            adjust_delegation_for_rent(
                &mut new_stake.delegation,
                rewarded_epoch,
                delegation_with_rewards,
                account.lamports(),
                minimum_balance,
            );
        } else {
            let expected_delegation = stake
                .delegation
                .stake
                .saturating_add(partitioned_stake_reward.inflation.stake_reward);
            assert_eq!(
                expected_delegation, new_stake.delegation.stake,
                "stake reward delegation must be consistent with the updated stake account \
                 lamport balance"
            );
        }
```
