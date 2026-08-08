## Title
Stake accounts withdrawn/closed during the multi-block partitioned reward distribution window cause already-computed staker rewards to be silently burned - ([File: runtime/src/bank/partitioned_epoch_rewards/distribution.rs])

## Summary
Agave's partitioned epoch-rewards mechanism computes each staker's reward once, at the epoch boundary, from a snapshot of the `StakesCache`, but only *pays it out* several blocks later when that staker's partition is processed. If the stake account is closed (fully withdrawn) by its own withdraw authority — an ordinary, unprivileged action — any time between the calculation block and its assigned distribution block, the lookup into the (now current) `StakesCache` fails and the previously calculated reward for that account is discarded instead of being paid, exactly mirroring the reported bug class where an entity removed from a dynamic list before the "payout" step causes value that was already earned to be permanently lost.

## Finding Description
Reward calculation happens once at the epoch boundary in `begin_partitioned_rewards()` [1](#0-0) , producing a list of `PartitionedStakeReward` entries that are hashed into up to `slots_per_epoch / 10` partitions and paid out one partition per block over the following blocks [2](#0-1) .

At the actual distribution block, `store_stake_accounts_in_partition()` re-looks-up each stake account from the *current* `StakesCache` (not the snapshot used for calculation) via `build_updated_stake_reward()`: [3](#0-2) 

If the account is no longer present, a `DistributionError::AccountNotFound` is returned and the caller simply adds the reward amount to `stake_reward_lamports_burned` / `block_reward_lamports_burned` instead of crediting the account: [4](#0-3) 

The code's own comment on `store_stake_accounts_in_partition()` explicitly states this should be impossible: *"Because stake accounts are checked in calculation, and further state mutation prevents by stake-program restrictions, there should never be rewards burned."* [5](#0-4) 

However, there is no such restriction in the codebase. `test_rewards_period_system_transfer` in the reward tests explicitly documents and verifies the opposite: *"lamports can be sent to stake accounts regardless of rewards period"*, and normal transactions are processed unimpeded during the whole reward interval [6](#0-5) . Nothing prevents a stake account's withdraw authority from calling `Withdraw` to fully drain and close their already-deactivated stake account after the epoch boundary but before their partition's distribution block is reached (the window can span up to 10% of an epoch's slots, per `get_reward_distribution_num_blocks`). Once the account is gone from `StakesCache`, the reward computed for it during calculation becomes unreachable and is burned in `distribute_epoch_rewards_in_partition()`: [7](#0-6) 

Note that `stake_reward_lamports_minted` (successfully paid rewards) is added to capitalization, but `stake_reward_lamports_burned` is never added to any account — the inflation reward that had already been earned and calculated for that staker for the prior epoch simply vanishes, matching the reported bug pattern of value becoming permanently stuck/lost because the reference to the entity was removed from the list used at payout time.

## Impact Explanation
A legitimate, unprivileged staker who deactivates and then withdraws/closes their stake account in the narrow window between the epoch-boundary reward calculation and their assigned partition's distribution block permanently loses the inflation reward they already earned for the prior epoch. This is a genuine loss of lamports that the protocol's own accounting (`epoch_rewards` sysvar `distributed_rewards`) marks as "distributed" even though no one receives them — i.e., rewards are computed but destroyed rather than paid, contradicting the invariant the code assumes. This is a real functional/economic bug in the reward-distribution path, though the loss falls on the account owner performing the withdrawal rather than a third party.

## Likelihood Explanation
This is trivially reachable by any staker: deactivate stake in advance so it is fully deactivated for the rewarded epoch (still earning a final "deactivating" reward), and then submit a `Withdraw` instruction that empties/closes the account at any point after the epoch boundary but before the specific block that processes that account's partition (a window of potentially many blocks, since the whole distribution window can span up to `slots_per_epoch / 10` blocks). No special privileges, timing races with validators, or coordination is required — only correctly timing a normal stake withdrawal.

## Recommendation
Either (a) explicitly disallow withdrawing/closing a stake account that has a pending, not-yet-distributed partitioned reward (e.g., check `EpochRewardStatus`/`epoch_rewards` sysvar active state in the stake program's `Withdraw` processor and reject/queue the instruction), or (b) settle each staker's owed reward against the withdrawal amount before the account is closed, or (c) credit the reward to the account being withdrawn (add stake_reward before it's zeroed out / prevent removing an entry that still has an outstanding accrued-but-undistributed reward), rather than silently discarding it as "burned."

## Proof of Concept
1. Stake account `S` delegates to vote account `V` and deactivates in epoch `E-1` so that its `deactivation_epoch == E-1`.
2. At the epoch `E` boundary, `begin_partitioned_rewards()` computes `S`'s deactivating-stake reward for epoch `E-1` and stores it in `all_stake_rewards`, then hashes it into one of several distribution partitions (`hash_rewards_into_partitions`), which are paid out over subsequent blocks [8](#0-7) .
3. Before the block corresponding to `S`'s partition arrives, the withdraw authority of `S` submits a `Withdraw` instruction that fully drains and closes `S` — this is not blocked, as confirmed by `test_rewards_period_system_transfer`, which asserts that ordinary account mutations succeed unconditionally "regardless of rewards period" [6](#0-5) .
4. `S` is now removed from `StakesCache`.
5. When `S`'s partition is later processed, `build_updated_stake_reward()` fails to find `S` in `stakes_cache_accounts` and returns `DistributionError::AccountNotFound` [3](#0-2) .
6. `store_stake_accounts_in_partition()` adds `S`'s already-earned reward to `stake_reward_lamports_burned`/`block_reward_lamports_burned` instead of crediting any account [9](#0-8) , and `distribute_epoch_rewards_in_partition()` never adds `stake_reward_lamports_burned` to capitalization [10](#0-9)  — the reward is permanently lost.

### Citations

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L241-274)
```rust
    pub(in crate::bank) fn begin_partitioned_rewards(
        &mut self,
        parent_epoch: Epoch,
        parent_slot: Slot,
        parent_block_height: u64,
        rewards_calculation: &PartitionedRewardsCalculation,
        rewards_metrics: &mut RewardsMetrics,
        thread_pool: &ThreadPool,
    ) -> u64 {
        let RewardCommissionLamportAmounts {
            distributed_lamports,
            distributed_to_incinerator_lamports,
            burned_lamports,
        } = self.distribute_reward_commissions(
            parent_epoch,
            rewards_calculation,
            rewards_metrics,
            thread_pool,
        );

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

**File:** runtime/src/bank/partitioned_epoch_rewards/mod.rs (L1082-1165)
```rust
    /// Test that lamports can be sent to stake accounts regardless of rewards period.
    #[test]
    fn test_rewards_period_system_transfer() {
        let validator_vote_keypairs = ValidatorVoteKeypairs::new_rand();
        let validator_keypairs = vec![&validator_vote_keypairs];
        let GenesisConfigInfo {
            mut genesis_config,
            mint_keypair,
            ..
        } = create_genesis_config_with_vote_accounts(
            1_000_000_000,
            &validator_keypairs,
            vec![1_000_000_000; 1],
        );

        // Add stake account to try to mutate
        let vote_key = validator_keypairs[0].vote_keypair.pubkey();
        let vote_account = genesis_config
            .accounts
            .iter()
            .find(|(address, _)| **address == vote_key)
            .map(|(_, account)| account)
            .unwrap()
            .clone();

        let new_stake_signer = Keypair::new();
        let new_stake_address = new_stake_signer.pubkey();
        let new_stake_account = Account::from(stake_utils::create_stake_account(
            &new_stake_address,
            &vote_key,
            &vote_account.into(),
            &genesis_config.rent,
            2_000_000_000,
        ));
        genesis_config
            .accounts
            .extend(vec![(new_stake_address, new_stake_account)]);

        let (mut previous_bank, bank_forks) = Bank::new_with_bank_forks_for_tests(&genesis_config);
        let num_slots_in_epoch = previous_bank.get_slots_in_epoch(previous_bank.epoch());
        assert_eq!(num_slots_in_epoch, 32);

        let transfer_amount = 5_000;

        for slot in 1..=num_slots_in_epoch + 2 {
            let bank = Bank::new_from_parent_with_bank_forks(
                bank_forks.as_ref(),
                previous_bank.clone(),
                SlotLeader::default(),
                slot,
            );

            // Fill bank_forks with banks with votes landing in the next slot
            // So that rewards will be paid out at the epoch boundary, i.e. slot = 32
            let tower_sync = TowerSync::new_from_slot(slot - 1, previous_bank.hash());
            let vote = vote_transaction::new_tower_sync_transaction(
                tower_sync,
                previous_bank.last_blockhash(),
                &validator_vote_keypairs.node_keypair,
                &validator_vote_keypairs.vote_keypair,
                &validator_vote_keypairs.vote_keypair,
                None,
            );
            bank.process_transaction(&vote).unwrap();

            // Insert a transfer transaction from the mint to new stake account
            let system_tx = system_transaction::transfer(
                &mint_keypair,
                &new_stake_address,
                transfer_amount,
                bank.last_blockhash(),
            );
            let system_result = bank.process_transaction(&system_tx);

            // Credits should always succeed
            assert!(system_result.is_ok());

            // Push a dummy blockhash, so that the latest_blockhash() for the transfer transaction in each
            // iteration are different. Otherwise, all those transactions will be the same, and will not be
            // executed by the bank except the first one.
            bank.register_unique_recent_blockhash_for_test();
            previous_bank = bank;
        }
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

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L249-252)
```rust
        let stake_account = stakes_cache_accounts
            .get(&partitioned_stake_reward.stake_pubkey)
            .ok_or(DistributionError::AccountNotFound)?
            .clone();
```

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L327-335)
```rust
    /// Store stake rewards in partition
    /// Returns DistributionResults containing the sum of all the rewards
    /// stored, the sum of all rewards burned, and the updated StakeRewards.
    /// Because stake accounts are checked in calculation, and further state
    /// mutation prevents by stake-program restrictions, there should never be
    /// rewards burned.
    ///
    /// Note: even if staker's reward is 0, the stake account still needs to be
    /// stored because credits observed has changed
```

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L393-407)
```rust
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
```
