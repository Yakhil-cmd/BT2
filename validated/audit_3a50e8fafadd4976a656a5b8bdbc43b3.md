### Title
Reward-partition size grows unboundedly with attacker-created stake accounts, stalling epoch-boundary blocks - ([File: runtime/src/bank/partitioned_epoch_rewards/mod.rs])

### Summary
`Bank::get_reward_distribution_num_blocks` caps the *number* of reward-distribution blocks/partitions at `slots_per_epoch / MAX_FACTOR_OF_REWARD_BLOCKS_IN_EPOCH` (10% of the epoch), but does not cap the *number of stake accounts per partition*. Once the total delegated stake-account count exceeds `partitioned_rewards_stake_account_stores_per_block * (slots_per_epoch/10)`, the number of partitions saturates at the cap while the per-partition account count keeps growing linearly with the total number of stake accounts. `EpochRewardsHasher` in `hash_rewards_into_partitions` distributes accounts pseudo-randomly across the fixed partition count, so an attacker who creates enough low-balance rent-exempt stake accounts delegated to one (or many) vote accounts can inflate the amount of work (`store_stake_accounts_in_partition` → `store_accounts` → `enqueue_off_chain_accounts_lt_hash_updates`) done in a single epoch-boundary partition block.

### Finding Description
`get_reward_distribution_num_blocks` [1](#0-0)  computes:
```
num_chunks = total_stake_accounts.div_ceil(partitioned_rewards_stake_account_stores_per_block)
num_chunks.clamp(1, (slots_per_epoch / 10).max(1))
```
This clamp bounds the **number of partitions/blocks**, not the **size of each partition**. `hash_rewards_into_partitions` [2](#0-1)  spreads `total_stake_accounts` reward entries across exactly `num_partitions` buckets using a hash of the stake pubkey — there is no per-bucket size limit. So once `total_stake_accounts` exceeds `partitioned_rewards_stake_account_stores_per_block * (slots_per_epoch/10)`, further growth in `total_stake_accounts` only increases the average number of accounts per partition (`total_stake_accounts / num_partitions`), which is exactly proportional to K (attacker-created accounts), with no upper bound.

Each partition is processed in a single block via `distribute_epoch_rewards_in_partition` → `store_stake_accounts_in_partition` [3](#0-2) , which iterates every stake account belonging to that partition, builds updated stake rewards, and calls `self.store_accounts(...)`. That store path invokes `enqueue_off_chain_accounts_lt_hash_updates` [4](#0-3) , which for each account in the partition performs a `load_with_fixed_root_do_not_populate_read_cache` plus a mix_in/mix_out `LtHash` job — again proportional to per-partition account count with no cap. This work must complete synchronously as part of producing/replaying that specific slot (the reward-distribution block), directly extending its critical-path processing time.

No signer/authority/rent-exempt check limits how many stake accounts a single funded user can create and delegate to a vote account; stake account creation and delegation are standard, permissionless operations. The only pre-existing mitigation, `MAX_FACTOR_OF_REWARD_BLOCKS_IN_EPOCH`, bounds the number of blocks used for distribution, but perversely this *causes* per-block work to increase once the account count outgrows the per-block-store budget, because the hasher will keep assigning more accounts into the same fixed set of partitions.

### Impact Explanation
This matches the "epoch-boundary halt / block-time stall" bounty category: an unprivileged, self-funded attacker can inflate the work done by a specific validator-produced/replayed block at every epoch boundary by an amount proportional to the number of stake accounts they create and delegate. Because the work (stake-account loads, `LtHash` mix_in/mix_out jobs, and `store_accounts_par`) is done inline within `distribute_partitioned_epoch_rewards()`/`freeze()` for that slot, in the worst case this can push per-block latency far beyond the target slot time, risking cluster-wide degradation at every epoch boundary (recurring, not one-off).

### Likelihood Explanation
Feasible: an attacker only needs standard `system_instruction::create_account` + `stake_instruction::initialize`/`delegate_stake` calls to create many rent-exempt stake accounts (minimum balance ~0.00228 SOL-ish per account on current rent parameters) delegated to a single (or few) vote accounts, over as many epochs/blocks as needed (bounded only by attacker's own funds and normal per-block compute/instruction limits, which do not prevent accumulation over time). This requires no validator/operator privileges, no leaked keys, and no protocol special-casing — it is a straightforward repeated use of a public instruction. The condition threshold (`stake_account_stores_per_block * slots_per_epoch/10`) is a concrete, computable number of accounts (order of low hundred-thousands depending on config), which is within reach of a moderately funded attacker over multiple epochs.

### Recommendation
Introduce an explicit cap on the maximum number of stake accounts assigned to any single partition (e.g., re-derive `num_partitions` so that `ceil(total_stake_accounts / num_partitions) <= partitioned_rewards_stake_account_stores_per_block` always holds, even if that means exceeding the `slots_per_epoch/10` block-count cap, or alternatively split partitions further within a block using bounded sub-batches, or reject the account-count clamp in favor of a lower bound on total reward-distribution slots that scales with account growth. At minimum, monitor/reject stake-account creation that would push per-partition sizes above a safe compute/time budget, and consider imposing a network-wide limit on the number of stake accounts delegated to a single vote account or the total number of stake accounts overall.

### Proof of Concept
```rust
// runtime/src/bank/partitioned_epoch_rewards/mod.rs (test-style PoC)
#[test]
fn test_partition_size_grows_unbounded_beyond_block_cap() {
    let (mut genesis_config, _mint_keypair) = create_genesis_config(1_000_000 * LAMPORTS_PER_SOL);
    // small epoch to make the 10%-of-epoch cap trigger quickly
    genesis_config.epoch_schedule = EpochSchedule::custom(1000, 1000, false);
    let mut accounts_db_config: AccountsDbConfig = ACCOUNTS_DB_CONFIG_FOR_TESTING;
    accounts_db_config.partitioned_epoch_rewards_config =
        PartitionedEpochRewardsConfig::new_for_test(10); // 10 stake accounts stored per block

    let bank = Bank::new_from_genesis(
        &genesis_config, Arc::new(RuntimeConfig::default()), Vec::new(), None,
        accounts_db_config, None, Some(SlotLeader::new_unique()), Arc::default(), None, None,
    );

    // max_partitions = slots_per_epoch / 10 = 100
    // per-block budget = 10 accounts/block => "designed" capacity = 100 * 10 = 1000 accounts
    let max_partitions = 100u64;
    let designed_capacity = max_partitions * 10;

    // Simulate attacker growth: create far more stake accounts than designed_capacity
    let attacker_accounts = designed_capacity * 50; // K = 50x over-subscription
    let stake_rewards = (0..attacker_accounts)
        .map(|_| Some(PartitionedStakeReward::new_random()))
        .collect::<PartitionedStakeRewards>();

    let num_blocks = bank.get_reward_distribution_num_blocks(&stake_rewards);
    // Number of blocks is capped...
    assert_eq!(num_blocks, max_partitions);

    // ...but per-partition size is NOT capped: it now averages 50x the intended
    // per-block budget of 10 accounts/block.
    let partition_indices = hash_rewards_into_partitions(
        &stake_rewards, &Hash::new_from_array([1; 32]), num_blocks as usize,
    );
    let max_partition_size = partition_indices.iter().map(|p| p.len()).max().unwrap();
    assert!(
        max_partition_size > 10 * 40, // far exceeds the configured per-block store budget of 10
        "expected partition size to grow unbounded with attacker account count, got {max_partition_size}"
    );
}
```
Expected assertions: `num_blocks` stays fixed at the epoch's 10%-of-slots cap regardless of `attacker_accounts`, while `max_partition_size` (and therefore the number of `store_accounts`/`enqueue_off_chain_accounts_lt_hash_updates` jobs executed in a single epoch-boundary block) scales linearly with `attacker_accounts`, demonstrating unbounded per-block work growth driven purely by attacker-controlled account count.

### Citations

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

**File:** runtime/src/bank/accounts_lt_hash.rs (L95-169)
```rust
    pub fn enqueue_off_chain_accounts_lt_hash_updates<'a>(
        &self,
        accounts: &impl StorableAccounts<'a>,
        thread_pool_for_loading_accounts: Option<&ThreadPool>,
    ) {
        if cfg!(debug_assertions) {
            // if debug assertions are on, we will check for duplicates
            use ahash::HashSetExt as _;
            let mut seen_accounts = ahash::HashSet::with_capacity(accounts.len());
            let mut duplicate_pubkeys = ahash::HashSet::with_capacity(0); // assume no duplicates
            for index in 0..accounts.len() {
                let pubkey = accounts.pubkey(index);
                if !seen_accounts.insert(pubkey) {
                    // we've already seen this account, so add it to the duplicates list
                    duplicate_pubkeys.insert(pubkey);
                }
            }
            if !duplicate_pubkeys.is_empty() {
                let mut duplicate_accounts = ahash::HashMap::<_, Vec<_>>::default();
                for duplicate_pubkey in duplicate_pubkeys {
                    for index in 0..accounts.len() {
                        let pubkey = accounts.pubkey(index);
                        if pubkey == duplicate_pubkey {
                            duplicate_accounts
                                .entry(pubkey)
                                .or_default()
                                .push(accounts.account(index, |account| account.take_account()));
                        }
                    }
                }
                panic!("duplicate accounts were enqueued for hashing: {duplicate_accounts:?}");
            }
        }

        let async_progress = &self.accounts_lt_hash_async_progress;
        let thread_pool_for_hashing_accounts = accounts_hasher_thread_pool();

        // A closure that does the loading and enqueueing, so code is shared
        // whether using the thread_pool_for_loading_accounts or not.
        let load_then_enqueue = |index| {
            let address = accounts.pubkey(index);
            let prev_account = self
                .rc
                .accounts
                .load_with_fixed_root_do_not_populate_read_cache(&self.ancestors, address)
                .map(|(account, _slot)| account);
            let curr_account = accounts.account(index, |account| {
                (account.lamports() != 0).then(|| account.take_account())
            });
            if prev_account.is_none() && curr_account.is_none() {
                // the account was ephemeral; skip it
            } else {
                // the account was modified; enqueue this update
                async_progress.spawn(
                    thread_pool_for_hashing_accounts,
                    AccountsLtHashUpdate {
                        address: *address,
                        prev_account,
                        curr_account,
                    },
                );
            }
        };

        if let Some(thread_pool_for_loading_accounts) = thread_pool_for_loading_accounts {
            // The previous version of accounts must be loaded before subsequent account
            // modifications occur, so ThreadPool::spawn() canot be used here.
            thread_pool_for_loading_accounts.install(|| {
                (0..accounts.len())
                    .into_par_iter()
                    .for_each(load_then_enqueue);
            });
        } else {
            (0..accounts.len()).for_each(load_then_enqueue);
        }
```
