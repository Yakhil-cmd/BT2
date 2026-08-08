### Title
Uncapped per-block reward-distribution work despite `get_reward_distribution_num_blocks` clamp - ([File: runtime/src/bank/partitioned_epoch_rewards/mod.rs])

### Finding Description
`Bank::get_reward_distribution_num_blocks` caps only the *number of blocks* used to distribute partitioned epoch rewards, not the *number of stake accounts processed per block*: [1](#0-0) 

`num_chunks = total_stake_accounts.div_ceil(partitioned_rewards_stake_account_stores_per_block())` is clamped to `[1, slots_per_epoch/MAX_FACTOR_OF_REWARD_BLOCKS_IN_EPOCH]`. When `total_stake_accounts = rewards.num_rewards()` grows far beyond `partitioned_rewards_stake_account_stores_per_block() * MAX_FACTOR_OF_REWARD_BLOCKS_IN_EPOCH`, the clamp saturates the *block count* at `slots_per_epoch/10`, but `total_stake_accounts` keeps growing unbounded.

`hash_rewards_into_partitions` then evenly hashes all `total_stake_accounts` entries across the fixed, capped number of partitions: [2](#0-1) 

Since the partition count is capped but `total_stake_accounts` is not, the number of entries per partition (`indices.len()` in `store_stake_accounts_in_partition`) grows linearly with the total number of delegated stake accounts once the cap kicks in. `store_stake_accounts_in_partition` then does O(partition size) work per block — iterating `indices`, calling `build_updated_stake_reward` per entry, and calling `self.store_accounts` over the whole partition: [3](#0-2) 

This is invoked once per block inside `distribute_partitioned_epoch_rewards`, which runs inline in block production/replay under the fixed slot-time budget: [4](#0-3) 

An unprivileged user can grow `total_stake_accounts` by creating many stake accounts and delegating them (System `CreateAccount` + Stake `DelegateStake`, directly or via CPI) before an epoch boundary, at the cost of rent-exempt reserve (`Rent::minimum_balance(StakeStateV2::size_of())`, a few thousand lamports) plus the minimum delegation amount defined in `stake_utils::get_minimum_delegation` (1 SOL when the `upgrade_bpf_stake_program_to_v5` feature is active, or as low as 1 lamport pre-feature): [5](#0-4) 

Every such delegated stake account, once activated, is included in `num_rewards()` for the epoch (even zero-reward entries are retained, per the code comment in `store_stake_accounts_in_partition`), inflating `total_stake_accounts` linearly with the number of accounts the attacker funds. No existing guard (signer, authority, rent-exempt, or arithmetic-overflow check) limits the *total number* of delegated stake accounts system-wide or bounds per-block distribution work independent of block count.

### Impact Explanation
Once `total_stake_accounts` exceeds `partitioned_rewards_stake_account_stores_per_block() * MAX_FACTOR_OF_REWARD_BLOCKS_IN_EPOCH`, the fixed number of distribution blocks (`slots_per_epoch/10`) must each process a proportionally larger, unbounded slice of stake accounts in `store_stake_accounts_in_partition`. Because this runs inline during block replay/production, exceeding the per-block time budget causes distribution blocks to miss their slot deadlines, matching the "epoch-boundary work must be bounded" invariant violation and the "epoch-boundary halt" bounty category (validators stalling/skipping slots while attempting to process oversized reward partitions).

### Likelihood Explanation
Feasibility scales with capital: pre-`upgrade_bpf_stake_program_to_v5` (minimum delegation = 1 lamport), an attacker only pays the rent-exempt reserve per stake account (a few thousand lamports each), making creation of tens of thousands of accounts (well beyond `MAX_PARTITIONED_REWARDS_PER_BLOCK` × 10 = 40,960) cheap and repeatable epoch after epoch. Post-feature-activation (minimum delegation = 1 SOL), the same attack requires proportionally more capital but is still purely a function of funds, with no protocol-level cap preventing it, and delegated lamports are recoverable later (not burned), lowering the effective long-term cost.

### Recommendation
Bound per-partition work independently of `total_stake_accounts`, e.g., by increasing the number of distribution blocks beyond the `slots_per_epoch/10` cap when necessary (accepting a longer, but bounded-per-block, distribution window), or by capping/streaming the number of stake-account entries processed per block regardless of partition assignment, and/or introducing a protocol-enforced ceiling on the number of stake accounts eligible for per-epoch reward processing per validator/stake authority.

### Proof of Concept
Extend the existing `test_get_reward_distribution_num_blocks_cap` test pattern in `runtime/src/bank/partitioned_epoch_rewards/mod.rs` into an invariant/fuzz test:
1. Configure a bank with a small `slots_per_epoch` and small `stake_account_stores_per_block` (as in `test_get_reward_distribution_num_blocks_cap`).
2. Sweep `total_stake_accounts` from `1x` to `100x` of `stake_account_stores_per_block * MAX_FACTOR_OF_REWARD_BLOCKS_IN_EPOCH`.
3. For each value, call `get_reward_distribution_num_blocks` to confirm the block count saturates at `slots_per_epoch/10` (already covered by existing tests), then call `hash_rewards_into_partitions` with that clamped count and measure the resulting max partition size (`partition_indices.iter().map(|p| p.len()).max()`).
4. Assert the max partition size grows roughly linearly with `total_stake_accounts` (no upper bound), then feed that partition into `store_stake_accounts_in_partition` under `measure_us!` and assert wall-clock time also grows unboundedly instead of staying within a fixed block-time budget (e.g., ~400ms equivalent), demonstrating the invariant violation.

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

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L127-150)
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

**File:** runtime/src/stake_utils.rs (L15-27)
```rust
/// The minimum stake amount that can be delegated, in lamports.
/// When this feature is added, it will be accompanied by an upgrade to the BPF Stake Program.
/// NOTE: This is also used to calculate the minimum balance of a delegated stake account,
/// which is the rent exempt reserve _plus_ the minimum stake delegation.
#[inline(always)]
pub fn get_minimum_delegation(upgrade_bpf_stake_program_to_v5_is_active: bool) -> u64 {
    if upgrade_bpf_stake_program_to_v5_is_active {
        const MINIMUM_DELEGATION_SOL: u64 = 1;
        MINIMUM_DELEGATION_SOL * LAMPORTS_PER_SOL
    } else {
        1
    }
}
```
