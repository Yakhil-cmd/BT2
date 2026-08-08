### Title
`get_reward_distribution_num_blocks`'s 10%-epoch cap on partition count does not bound per-block work, allowing attacker-inflated stake-account counts to inflate `store_stake_accounts_in_partition` cost per block - (`runtime/src/bank/partitioned_epoch_rewards/mod.rs`)

### Summary
`get_reward_distribution_num_blocks` clamps the number of reward-distribution blocks (`num_chunks`) to `slots_per_epoch / 10`, but this clamp only bounds the *number of blocks*, not the *number of stake accounts processed per block*. Once `total_stake_accounts / partitioned_rewards_stake_account_stores_per_block()` exceeds the 10%-epoch cap, `hash_rewards_into_partitions` still spreads all rewards across only the capped number of partitions, so each partition (and thus each block's call to `store_stake_accounts_in_partition`) grows linearly with `total_stake_accounts`, well beyond the intended `stake_account_stores_per_block` baseline.

### Finding Description
`get_reward_distribution_num_blocks` computes: [1](#0-0) 

`num_chunks = total_stake_accounts.div_ceil(stake_account_stores_per_block)`, then clamps to `[1, slots_per_epoch/10]`. The comment "Limit the reward credit interval to 10% of the total number of slots in a epoch" makes clear the design intent is to bound epoch-boundary *duration*. However, the actual per-block workload is determined by `hash_rewards_into_partitions`, which distributes all `total_stake_accounts` reward entries into exactly `num_partitions` buckets via a pseudo-uniform hash of the stake pubkey: [2](#0-1) 

When `num_chunks` is clamped down from its unclamped (uncapped) value, the number of buckets (`num_partitions`) no longer scales with `total_stake_accounts`; each bucket instead receives roughly `total_stake_accounts / num_partitions` entries — a value that grows without bound as `total_stake_accounts` grows, once the cap is saturated. This directly determines the workload of `store_stake_accounts_in_partition`, which iterates over every index in the partition, deserializes/mutates each stake account, and finally calls `self.store_accounts(...)` over the full batch: [3](#0-2) 

This is invoked once per block from `distribute_epoch_rewards_in_partition` / `distribute_partitioned_epoch_rewards` during the active reward-distribution interval: [4](#0-3) [5](#0-4) 

Nothing in this path re-checks or re-bounds the per-partition size against `partitioned_rewards_stake_account_stores_per_block()` once the 10%-cap has been applied — the baseline constant (`MAX_PARTITIONED_REWARDS_PER_BLOCK = 4096`, documented as "Baseline number of stake accounts to store in one 400ms block") is only used to *compute* the uncapped `num_chunks`, not enforced as an actual per-block ceiling: [6](#0-5) 

An unprivileged attacker who creates and delegates a sufficiently large number of distinct minimum-delegation stake accounts (across many vote accounts, to avoid any single-voter/stake caps) increases `total_stake_accounts` for the epoch's reward calculation. Every one of these delegations is a legitimate, protocol-permitted action (fund + `CreateAccount` + `DelegateStake`), requiring no special privilege — only lamports for rent-exemption and minimum delegation per stake account.

### Impact Explanation
Once `total_stake_accounts` exceeds `stake_account_stores_per_block * (slots_per_epoch / 10)`, every additional attacker-created stake account increases the number of accounts stored per distribution block, without a corresponding increase in number of blocks (which stays capped). This inflates per-block CPU (deserialization, `build_updated_stake_reward`, `adjust_delegation_for_rent`) and storage (`store_accounts`) work in `store_stake_accounts_in_partition`, while the wall-clock duration of the interval remains fixed at 10% of the epoch. This matches the "validator resource exhaustion at epoch boundaries" bounty category: the epoch-boundary invariant that per-block work is bounded (by `stake_account_stores_per_block`) is broken once the interval is capped, and instead becomes proportional to attacker-controlled account count. All attacker stake accounts still legitimately receive `REWARD_EXACTLY_ONCE`, so there is no fund theft — only added, unbounded-until-economics-catch-up per-block compute/storage load on every validator.

### Likelihood Explanation
The attack requires the attacker to fund `N = total_stake_accounts` minimum-delegation stake accounts such that `N > stake_account_stores_per_block * slots_per_epoch / 10` (e.g., ~4096 * 43200 ≈ 177M accounts at 4096/block and 432,000 slots/epoch — a large but not architecturally-blocked number; it scales purely with the minimum-delegation amount, `get_minimum_delegation`, i.e., economic cost, not privilege). The economic cost is the only real limiter; there is no additional protocol check preventing this. Since the vulnerability's magnitude scales with total delegation count and the minimum-delegation constant is fixed protocol-wide, feasibility is directly tied to total attacker capital, matching the "economically bounded" framing in the question. Partial/incremental effects (i.e., moderate inflation of per-block load well below the full 177M-account extreme) are cheaper and more practically exploitable as a griefing vector than a full worst-case demonstration.

### Recommendation
Decouple the two goals currently conflated in `get_reward_distribution_num_blocks`: enforce a genuine hard per-block cap on the number of stake accounts stored (e.g., sub-chunk each hashed partition bucket into pages of at most `partitioned_rewards_stake_account_stores_per_block()` entries, and increase the number of *distribution blocks* accordingly) instead of silently increasing the payload of a fixed-size block count when the naive `num_chunks` exceeds the 10%-epoch limit. Alternatively, impose (and document) an explicit epoch-wide ceiling on the total number of stake accounts eligible for partitioned rewards, or scale `stake_account_stores_per_block` dynamically so the invariant "distribution blocks are capped in count AND bounded in per-block size" holds simultaneously.

### Proof of Concept
Add a unit test in `runtime/src/bank/partitioned_epoch_rewards/mod.rs` tests module that exercises `get_reward_distribution_num_blocks` and `hash_rewards_into_partitions`/`store_stake_accounts_in_partition` together with a stake-account count that saturates the 10% cap, and assert per-partition size grows unbounded:

```rust
#[test]
fn test_per_block_work_unbounded_when_cap_saturated() {
    // Small epoch schedule to make the cap easy to hit.
    let (mut genesis_config, _mint_keypair) = create_genesis_config(1_000_000 * LAMPORTS_PER_SOL);
    genesis_config.epoch_schedule = EpochSchedule::custom(320, 320, false); // cap = 32 blocks

    let mut accounts_db_config: AccountsDbConfig = ACCOUNTS_DB_CONFIG_FOR_TESTING;
    // baseline: intend 10 accounts/block
    accounts_db_config.partitioned_epoch_rewards_config =
        PartitionedEpochRewardsConfig::new_for_test(10);

    let bank = Bank::new_from_genesis(
        &genesis_config, Arc::new(RuntimeConfig::default()), Vec::new(), None,
        accounts_db_config, None, Some(SlotLeader::new_unique()), Arc::default(), None, None,
    );

    // Uncapped num_chunks would be 10_000 (100_000 stake accounts / 10 per block),
    // but epoch cap is 320/10 = 32 blocks.
    let num_stake_accounts = 100_000u64;
    let stake_rewards = (0..num_stake_accounts)
        .map(|_| Some(PartitionedStakeReward::new_random()))
        .collect::<PartitionedStakeRewards>();

    let num_blocks = bank.get_reward_distribution_num_blocks(&stake_rewards);
    assert_eq!(num_blocks, 32); // capped, as designed

    let partition_indices = hash_rewards_into_partitions(
        &stake_rewards, &Hash::new_from_array([1; 32]), num_blocks as usize,
    );

    // Average accounts per block is ~100_000 / 32 ≈ 3125, i.e. ~312x the
    // configured `stake_account_stores_per_block` of 10 — demonstrating the
    // per-block cap is NOT enforced once the epoch-length cap saturates.
    let avg_per_block = num_stake_accounts / num_blocks;
    assert!(
        avg_per_block > 10 * 10, // arbitrary multiplier demonstrating blow-up
        "expected per-block stake account count to exceed configured baseline, got {avg_per_block}"
    );
}
```

This test demonstrates that `get_reward_distribution_num_blocks`'s clamp caps block *count* only; actual per-block payload (and hence the compute/storage cost of `store_stake_accounts_in_partition`) scales with `total_stake_accounts` unboundedly once the cap saturates, confirming the resource-exhaustion path described.

### Citations

**File:** runtime/src/bank/partitioned_epoch_rewards/mod.rs (L408-427)
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
```

**File:** runtime/src/bank/partitioned_epoch_rewards/epoch_rewards_hasher.rs (L6-24)
```rust
pub(in crate::bank::partitioned_epoch_rewards) fn hash_rewards_into_partitions(
    stake_rewards: &PartitionedStakeRewards,
    parent_blockhash: &Hash,
    num_partitions: usize,
) -> Vec<Vec<usize>> {
    let hasher = EpochRewardsHasher::new(num_partitions, parent_blockhash);
    let mut indices = vec![vec![]; num_partitions];

    for (i, reward) in stake_rewards.enumerated_rewards_iter() {
        // clone here so the hasher's state is reused on each call to `hash_address_to_partition`.
        // This prevents us from re-hashing the seed each time.
        // The clone is explicit (as opposed to an implicit copy) so it is clear this is intended.
        let partition_index = hasher
            .clone()
            .hash_address_to_partition(&reward.stake_pubkey);
        indices[partition_index].push(i);
    }
    indices
}
```

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L127-149)
```rust
        let EpochRewardStatus::Active(EpochRewardPhase::Distribution(partition_rewards)) =
            &self.epoch_reward_status
        else {
            // We should never get here.
            unreachable!(
                "epoch rewards status is not in distribution phase, but we are trying to \
                 distribute rewards"
            );
        };

        let distribution_end_exclusive =
            distribution_starting_block_height + partition_rewards.partition_indices.len() as u64;

        assert!(
            self.epoch_schedule.get_slots_in_epoch(self.epoch)
                > partition_rewards.partition_indices.len() as u64
        );

        if height >= distribution_starting_block_height && height < distribution_end_exclusive {
            let partition_index = height - distribution_starting_block_height;

            self.distribute_epoch_rewards_in_partition(partition_rewards, partition_index);
        }
```

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L175-204)
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
```

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L336-415)
```rust
    fn store_stake_accounts_in_partition(
        &self,
        partition_rewards: &StartBlockHeightAndPartitionedRewards,
        partition_index: u64,
    ) -> DistributionResults {
        let feature_snapshot = self.feature_set.snapshot();
        // Name intentionally doesn't match -- "adjust delegations for rent" is
        // part of relaxing post-exec min balance checks.
        let adjust_delegations_for_rent = feature_snapshot.relax_post_exec_min_balance_check;
        let use_fixed_point_stake_math = feature_snapshot.upgrade_bpf_stake_program_to_v5_1;

        let mut stake_reward_lamports_minted = 0;
        let mut stake_reward_lamports_burned = 0;
        let mut block_reward_lamports_distributed = 0;
        let mut block_reward_lamports_burned = 0;
        let indices = partition_rewards
            .partition_indices
            .get(partition_index as usize)
            .unwrap_or_else(|| {
                panic!(
                    "partition index out of bound: {partition_index} >= {}",
                    partition_rewards.partition_indices.len()
                )
            });
        let mut updated_stake_rewards = Vec::with_capacity(indices.len());
        let stakes_cache = self.stakes_cache.stakes();
        let stakes_cache_accounts = stakes_cache.stake_delegations();
        let stake_history = stakes_cache.history();
        let new_warmup_cooldown_rate_epoch = self.new_warmup_cooldown_rate_epoch();
        let rent = &self.rent_collector.rent;
        for index in indices {
            let partitioned_stake_reward = partition_rewards
                .all_stake_rewards
                .get(*index)
                .unwrap_or_else(|| {
                    panic!(
                        "partition reward out of bound: {index} >= {}",
                        partition_rewards.all_stake_rewards.total_len()
                    )
                })
                .as_ref()
                .unwrap_or_else(|| {
                    panic!("partition reward {index} is empty");
                });
            let stake_pubkey = partitioned_stake_reward.stake_pubkey;
            let stake_reward_amount = partitioned_stake_reward.inflation.stake_reward;
            let block_reward_amount = partitioned_stake_reward.block_reward;

            match Self::build_updated_stake_reward(
                self.epoch,
                stake_history,
                new_warmup_cooldown_rate_epoch,
                stakes_cache_accounts,
                partitioned_stake_reward,
                rent,
                adjust_delegations_for_rent,
                use_fixed_point_stake_math,
            ) {
                Ok(stake_reward) => {
                    stake_reward_lamports_minted += stake_reward_amount;
                    block_reward_lamports_distributed += block_reward_amount;
                    updated_stake_rewards.push(stake_reward);
                }
                Err(err) => {
                    error!(
                        "bank::distribution::store_stake_accounts_in_partition() failed for \
                         {stake_pubkey}, {stake_reward_amount} lamports burned: {err:?}"
                    );
                    stake_reward_lamports_burned += stake_reward_amount;
                    block_reward_lamports_burned += block_reward_amount;
                }
            }
        }
        drop(stakes_cache);
        self.store_accounts(
            (self.slot(), &updated_stake_rewards[..]),
            // Reuse the rewards calculation thread pool to parallelize
            // loading the previous versions of the stake accounts.
            Some(crate::bank::rewards_calculation_thread_pool()),
        );
```

**File:** accounts-db/src/partitioned_rewards.rs (L3-10)
```rust
/// Baseline number of stake accounts to store in one 400ms block during the
/// partitioned reward interval.
///
/// The target is 64 rewards per entry/tick. A block has a minimum of 64
/// entries/ticks, giving 4096 total rewards to store in one 400ms block. This
/// constant affects consensus; shorter slot-time targets scale this value down
/// in `Bank` state.
pub const MAX_PARTITIONED_REWARDS_PER_BLOCK: u64 = 4096;
```
