### Title
Panic-inducing `assert_eq!` in reward distribution can be triggered by a normal stake-account owner between epoch-boundary calculation and distribution - ([File: runtime/src/bank/partitioned_epoch_rewards/distribution.rs])

### Summary
`build_updated_stake_reward` recomputes each stake account's post-reward delegation using the **current** (distribution-time) `StakesCache` entry, while the reward amount baked into `PartitionedStakeReward` was computed **earlier**, at epoch-boundary calculation time. If the two states diverge and the `relax_post_exec_min_balance_check` (`adjust_delegations_for_rent`) feature-gated path is not taken, the code falls back to a hard `assert_eq!` that panics instead of returning a `DistributionError`.

### Finding Description
Partitioned epoch rewards are computed once, at the first block of a new epoch, into a `PartitionedStakeRewards` list via `calculate_stake_rewards_and_commissions` [1](#0-0) . Distribution to individual stake accounts is then spread out over up to 10% of the epoch's slots by `get_reward_distribution_num_blocks` [2](#0-1) , with each block's `store_stake_accounts_in_partition` looking up the stake account from the *live* `stakes_cache` at distribution time, not a snapshot from calculation time [3](#0-2) .

Inside `build_updated_stake_reward`, when `adjust_delegations_for_rent` is `false`, the code asserts that the *current* on-chain `delegation.stake` plus the pre-computed `inflation.stake_reward` exactly equals the delegation value that was captured during the earlier calculation phase: [4](#0-3) 

Between the calculation block and the (potentially many blocks later) distribution block for a specific stake account, that account's owner can execute ordinary, permissionless stake-program instructions (e.g. `Split`, `Merge`, `Deactivate`/`Delegate`, `Redelegate`) that change `delegation.stake` for that same pubkey. Because `store_stake_accounts_in_partition` reads the *current* `stakes_cache_accounts` state rather than a value frozen at calculation time [5](#0-4) , the `expected_delegation` computed from the live account can differ from `new_stake.delegation.stake` (the value baked into `partitioned_stake_reward.inflation.stake` during calculation), causing the `assert_eq!` to fail. This function is invoked deterministically by every validator while replaying/producing the same distribution-partition block, so the panic is not local — it is a state-transition function executed identically across the whole cluster.

This is a structural analog of the reported issue: a single actor's action injected into a multi-step batched process (rebalancing across markets vs. reward distribution across blocks) can abort the entire pipeline for everyone, because the code assumes external state (external market responsiveness / stake account state) will remain unchanged between the plan phase and the execute phase, and has no graceful fallback other than a panic when that assumption is violated on the un-gated path.

### Impact Explanation
An `assert_eq!` panic inside bank replay/processing is a process abort (`panic!` in `debug_assertions`-independent code, i.e. it always aborts in this call site since `assert_eq!` is not `debug_assert_eq!`). Because `distribute_epoch_rewards_in_partition`/`store_stake_accounts_in_partition` run as part of normal block processing (called for every partition block during the reward-distribution window) [6](#0-5) , all honest validators executing/replaying that block would hit the same panic and crash simultaneously, producing a cluster-wide halt at an epoch boundary — squarely within the accepted "epoch-boundary halt" impact category.

### Likelihood Explanation
Likelihood depends entirely on whether the `relax_post_exec_min_balance_check` feature (which gates `adjust_delegations_for_rent`) is active. I was **not able to conclusively determine from the indexed code whether this feature is already activated on mainnet/by default** — `grep_search` located references in `feature-set/src/lib.rs` and elsewhere, but the index did not surface the feature's activation status/epoch. If the feature is still inactive (or can be temporarily deactivated/rolled back, or the assert path is reachable via `recalculate_stake_rewards` after a snapshot restore that resets `feature_set` — as exercised by the test at `runtime/src/bank/partitioned_epoch_rewards/calculation.rs:3062` which explicitly resets `bank.feature_set = Arc::new(FeatureSet::default())` before recalculating rewards [7](#0-6) ), the non-adjusted/assert branch becomes reachable in production code paths, and any staker performing ordinary stake operations during the multi-block distribution window could trigger it. Given this significant unresolved dependency on feature-activation state, I cannot assert this is currently exploitable with full confidence.

### Recommendation
Replace the `assert_eq!` in `build_updated_stake_reward` with a non-panicking `DistributionError` variant (mirroring the existing `ArithmeticOverflow`/`UnableToSetState`/`AccountNotFound` error handling already used in the same function) so that a mismatch — however it arises — is degraded to burning that individual stake reward (as `store_stake_accounts_in_partition`'s `Err` branch already does) rather than aborting the entire validator process. Additionally, confirm whether `relax_post_exec_min_balance_check` is unconditionally active for all production cluster configurations and, if not, prioritize activation or add a defensive fallback to the `adjust_delegation_for_rent` behavior regardless of the feature flag during distribution.

### Proof of Concept
Not independently reproduced against a live cluster; based on static code-path analysis of `distribution.rs`. A conceptual PoC:
1. Stake account `S` delegates to vote account `V` and is delegated stake `X` lamports.
2. Epoch boundary block calculates rewards; `PartitionedStakeReward` for `S` records `inflation.stake.delegation.stake = X + reward`, to be applied several blocks later (partition assigned via `hash_rewards_into_partitions`).
3. Before `S`'s assigned distribution block is processed, `S`'s owner submits a `Split`/`Merge`/`Redelegate` instruction that changes `S`'s live `delegation.stake` to some `Y != X`.
4. When `S`'s distribution partition block is processed, `store_stake_accounts_in_partition` -> `build_updated_stake_reward` computes `expected_delegation = Y + reward`, which no longer equals the calculation-time `new_stake.delegation.stake = X + reward`, and (absent the rent-adjustment feature) panics via `assert_eq!`, crashing every validator processing that block.

### Citations

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L780-791)
```rust
    fn calculate_stake_rewards_and_commissions<'a>(
        &self,
        stake_history: &StakeHistory,
        stake_delegations: Vec<(&'a Pubkey, &'a StakeAccount<Delegation>)>,
        cached_vote_accounts: CachedVoteAccounts<'_>,
        rewarded_epoch: Epoch,
        point_value: PointValue,
        ag_epoch_type: &AlpenglowEpochType,
        thread_pool: &ThreadPool,
        reward_calc_tracer: Option<impl RewardCalcTracer>,
        metrics: &mut RewardsMetrics,
    ) -> (RewardCommissions, StakeRewardCalculation) {
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L3060-3064)
```rust
        // Simulate snapshot restore: re-apply features from accounts and
        // rebuild epoch_reward_status from snapshot-stable state.
        bank.feature_set = Arc::new(FeatureSet::default());
        let thread_pool = ThreadPoolBuilder::new().num_threads(1).build().unwrap();
        bank.initialize_after_snapshot_restore(|| &thread_pool);
```

**File:** runtime/src/bank/partitioned_epoch_rewards/mod.rs (L408-428)
```rust
    /// Calculate the number of blocks required to distribute rewards to all stake accounts.
    pub(super) fn get_reward_distribution_num_blocks(
        &self,
        rewards: &PartitionedStakeRewards,
    ) -> u64 {
        let total_stake_accounts = rewards.num_rewards();
        if self.epoch_schedule.warmup && self.epoch < self.first_normal_epoch() {
            1
        } else {
            const MAX_FACTOR_OF_REWARD_BLOCKS_IN_EPOCH: u64 = 10;
            let num_chunks = total_stake_accounts
                .div_ceil(self.partitioned_rewards_stake_account_stores_per_block() as usize)
                as u64;

            // Limit the reward credit interval to 10% of the total number of slots in a epoch
            num_chunks.clamp(
                1,
                (self.epoch_schedule.slots_per_epoch / MAX_FACTOR_OF_REWARD_BLOCKS_IN_EPOCH).max(1),
            )
        }
    }
```

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L175-224)
```rust
    fn distribute_epoch_rewards_in_partition(
        &self,
        partition_rewards: &StartBlockHeightAndPartitionedRewards,
        partition_index: u64,
    ) {
        let pre_capitalization = self.capitalization();
        let (
            DistributionResults {
                stake_reward_lamports_minted,
                stake_reward_lamports_burned,
                block_reward_lamports_distributed,
                block_reward_lamports_burned,
                updated_stake_rewards,
            },
            store_stake_accounts_us,
        ) = measure_us!(self.store_stake_accounts_in_partition(partition_rewards, partition_index));

        // increase total capitalization by the distributed rewards
        self.capitalization
            .fetch_add(stake_reward_lamports_minted, Relaxed);

        // decrease total capitalization by burned block rewards
        self.capitalization
            .fetch_sub(block_reward_lamports_burned, Relaxed);

        // decrease distributed capital from epoch rewards sysvar
        self.update_epoch_rewards_sysvar(
            stake_reward_lamports_minted + stake_reward_lamports_burned,
            block_reward_lamports_distributed + block_reward_lamports_burned,
        );

        // update reward history for this partitioned distribution
        self.update_reward_history_in_partition(&updated_stake_rewards);

        let metrics = RewardsStoreMetrics {
            pre_capitalization,
            post_capitalization: self.capitalization(),
            total_stake_accounts_count: partition_rewards.all_stake_rewards.num_rewards(),
            total_num_partitions: partition_rewards.partition_indices.len(),
            partition_index,
            store_stake_accounts_us,
            store_stake_accounts_count: updated_stake_rewards.len(),
            distributed_rewards: stake_reward_lamports_minted,
            burned_rewards: stake_reward_lamports_burned,
            distributed_block_rewards: block_reward_lamports_distributed,
            burned_block_rewards: block_reward_lamports_burned,
        };

        report_partitioned_reward_metrics(self, metrics);
    }
```

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L249-261)
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
```

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L284-294)
```rust
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

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L361-367)
```rust
        let stakes_cache = self.stakes_cache.stakes();
        let stakes_cache_accounts = stakes_cache.stake_delegations();
        let stake_history = stakes_cache.history();
        let new_warmup_cooldown_rate_epoch = self.new_warmup_cooldown_rate_epoch();
        let rent = &self.rent_collector.rent;
        for index in indices {
            let partitioned_stake_reward = partition_rewards
```
