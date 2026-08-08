The claim in the prompt is refuted by the code itself. `get_reward_distribution_num_blocks` explicitly clamps `num_partitions` (via `num_chunks.clamp(1, (slots_per_epoch / MAX_FACTOR_OF_REWARD_BLOCKS_IN_EPOCH).max(1))`) so it can never exceed roughly 10% of the epoch's slot count, no matter how many stake rewards exist: [1](#0-0) 

This means an attacker inflating `total_stake_accounts` by mass-creating minimal stake delegations only grows `num_chunks` before the clamp; after the clamp, `num_partitions` is capped at `slots_per_epoch / 10` (minimum 1), which is always strictly less than `slots_per_epoch` for any realistic (non-degenerate) `EpochSchedule`. The existing unit test `test_get_reward_distribution_num_blocks_cap` demonstrates that even 4x–5x the per-block capacity in stake rewards still caps the number of blocks at the same value: [2](#0-1) 

Since `num_partitions` returned from `get_reward_distribution_num_blocks` is what becomes `partition_rewards.partition_indices.len()` used in the assertion inside `distribute_partitioned_epoch_rewards`, and that value is architecturally bounded below `slots_per_epoch` by the clamp — not by attacker-controlled stake account count — the assertion: [3](#0-2) 

cannot be driven to fail purely by mass-creating tiny stake delegations. There is also a dedicated regression test, `test_distribute_partitioned_epoch_rewards_too_many_partitions`, which confirms the assertion only fires when `partition_indices` is artificially constructed (in the test) to exceed `slots_per_epoch + 1` — a scenario that cannot arise from the normal calculation path guarded by the clamp: [4](#0-3) 

#No Vulnerability found for this question.

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

**File:** runtime/src/bank/partitioned_epoch_rewards/mod.rs (L767-793)
```rust
        let check_num_reward_distribution_blocks =
            |num_stakes: u64, expected_num_reward_distribution_blocks: u64| {
                // Given the short epoch, i.e. 32 slots, we should cap the number of reward distribution blocks to 32/10 = 3.
                let stake_rewards = (0..num_stakes)
                    .map(|_| Some(PartitionedStakeReward::new_random()))
                    .collect::<PartitionedStakeRewards>();

                assert_eq!(
                    bank.get_reward_distribution_num_blocks(&stake_rewards),
                    expected_num_reward_distribution_blocks
                );
            };

        for test_record in [
            // num_stakes, expected_num_reward_distribution_blocks
            (0, 1),
            (1, 1),
            (stake_account_stores_per_block, 1),
            (2 * stake_account_stores_per_block - 1, 2),
            (2 * stake_account_stores_per_block, 2),
            (3 * stake_account_stores_per_block - 1, 3),
            (3 * stake_account_stores_per_block, 3),
            (4 * stake_account_stores_per_block, 3), // cap at 3
            (5 * stake_account_stores_per_block, 3), //cap at 3
        ] {
            check_num_reward_distribution_blocks(test_record.0, test_record.1);
        }
```

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L137-143)
```rust
        let distribution_end_exclusive =
            distribution_starting_block_height + partition_rewards.partition_indices.len() as u64;

        assert!(
            self.epoch_schedule.get_slots_in_epoch(self.epoch)
                > partition_rewards.partition_indices.len() as u64
        );
```

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L488-513)
```rust
    #[test]
    #[should_panic(expected = "self.epoch_schedule.get_slots_in_epoch")]
    fn test_distribute_partitioned_epoch_rewards_too_many_partitions() {
        let (genesis_config, _mint_keypair) = create_genesis_config(1_000_000 * LAMPORTS_PER_SOL);
        let mut bank = Bank::new_for_tests(&genesis_config);

        let expected_num = 1;

        let stake_rewards = (0..expected_num)
            .map(|_| Some(PartitionedStakeReward::new_random()))
            .collect::<PartitionedStakeRewards>();

        let partition_indices = hash_rewards_into_partitions(
            &stake_rewards,
            &Hash::new_from_array([1; 32]),
            bank.epoch_schedule().slots_per_epoch as usize + 1,
        );

        bank.set_epoch_reward_status_distribution(
            bank.block_height(),
            Arc::new(stake_rewards),
            partition_indices,
        );

        bank.distribute_partitioned_epoch_rewards();
    }
```
