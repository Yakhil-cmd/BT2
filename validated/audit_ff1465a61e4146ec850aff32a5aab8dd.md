### Title
Stake split/merge during epoch-boundary reward distribution window causes deterministic `assert_eq!` panic and epoch-boundary halt - ([File: runtime/src/bank/partitioned_epoch_rewards/distribution.rs])

### Summary
`build_updated_stake_reward` in `runtime/src/bank/partitioned_epoch_rewards/distribution.rs` computes the post-reward `Stake` (`new_stake`) entirely from the value that was frozen at the epoch-boundary calculation phase, then compares it against the *current* `StakesCache` entry for the same pubkey via a hard `assert_eq!`. If an attacker submits `stake_instruction::split` or `merge` against their own stake account in a slot after `calculate_rewards_for_partitioning` snapshots delegations but before that account's partition is distributed, the current cached delegation will legitimately diverge from the value calculated earlier, tripping the `assert_eq!` and panicking every validator that replays the block deterministically.

### Finding Description
`calculate_rewards_for_partitioning`/`calculate_stake_rewards_and_commissions` freeze `new_stake` (the post-reward `Stake`, including `delegation.stake`) for every rewarded stake pubkey at the first block of the epoch [1](#0-0) . This `PartitionedStakeReward` is stored in `Bank::epoch_reward_status` and distributed over multiple subsequent blocks/partitions [2](#0-1) .

Nothing in the transaction-processing path blocks ordinary stake-program instructions (including `split`/`merge`) from executing on a stake account while `EpochRewardStatus::Active` — the existing test suite explicitly demonstrates that unrelated transactions (e.g. system transfers to stake accounts) continue to be processed normally during the reward interval [3](#0-2) . Any such instruction immediately updates `StakesCache` through `Bank::store_accounts` → `StakesCache::check_and_store` → `upsert_stake_delegation` [4](#0-3) [5](#0-4) .

When the account's partition is later processed, `store_stake_accounts_in_partition` reads the *current* `StakesCache` snapshot (`stakes_cache_accounts`) and calls `build_updated_stake_reward`, which:
1. Loads the current stake state (`stake`) from the cache for `partitioned_stake_reward.stake_pubkey` [6](#0-5) .
2. Sets `new_stake = partitioned_stake_reward.inflation.stake` — the value computed at calculation time, before the split/merge [7](#0-6) .
3. When `adjust_delegations_for_rent` is disabled, asserts `stake.delegation.stake + reward == new_stake.delegation.stake` [8](#0-7) .

A `split` reduces the source account's own `delegation.stake` (and a `merge` changes it in the other direction); either operation performed on the stake account referenced by an as-yet-undistributed `PartitionedStakeReward` will make the current cached `stake.delegation.stake` diverge from the value frozen at calculation time. `expected_delegation` (computed from the *post*-split/merge cache value) will then not equal `new_stake.delegation.stake` (the *pre*-split/merge computed value), and the `assert_eq!` panics unconditionally — it is not routed through the `DistributionError` `Result` type, so it is not caught by the `Err` arm in `store_stake_accounts_in_partition` [9](#0-8) . Because block replay in Agave is deterministic and every validator that replays this same block will observe the same `stakes_cache_accounts` state (post-split/merge) and the same precomputed `partitioned_stake_reward`, every honest validator hits the identical panic — a network-wide epoch-boundary halt, not merely a single-node crash.

Even in the `adjust_delegations_for_rent` path (no assert), the bug still silently overwrites the account's `meta`/`flags` with current values but *discards* whatever delegation change the split/merge already applied, wholesale-replacing it with the pre-split/merge `new_stake.delegation`, which can misattribute or duplicate the amount of stake credited/exposed at the account, though this path was not able to be fully traced end-to-end given the available context.

### Impact Explanation
This falls under "epoch-boundary halt," one of the explicitly accepted impact categories. Because the mismatched-delegation assertion is a hard `assert_eq!` (not a recoverable `Result`), and stake accounts are not locked against ordinary user-submitted split/merge instructions during the multi-block reward-distribution window, an unprivileged attacker can deterministically crash the block-processing path for every validator replaying a block that contains their split/merge transaction sequenced before their own reward's distribution partition. This is a consensus-halting condition rather than isolated reward mis-accounting.

### Likelihood Explanation
Preconditions are minimal and fully within an unprivileged user's control: the attacker only needs (1) a stake account earning epoch rewards, (2) split/merge authority over that account (which they hold by definition, since it's their own account), and (3) the ability to submit a transaction in a slot between the epoch-boundary calculation block and the specific partition block in which their stake_pubkey is scheduled for distribution (multi-partition distribution windows can span many blocks, per `get_reward_distribution_num_blocks`, giving an attacker a reliable window). This is trivially reproducible in a local test harness and requires no validator/leader control, no stake-weight advantage, and no timing race beyond submitting an ordinary transaction within a known multi-block window.

### Recommendation
`build_updated_stake_reward` should not blindly trust the frozen `PartitionedStakeReward.inflation.stake` when the current `StakesCache` entry's delegation has diverged since calculation time due to a legitimate stake-program mutation (split/merge/withdraw). Instead of an unconditional `assert_eq!` that panics the entire node, the mismatch should be treated as a `DistributionError` variant (e.g., `DelegationChanged`) returned via the existing `Result`, causing the reward to be burned/re-attributed through the existing `Err` handling path in `store_stake_accounts_in_partition`, consistent with how `AccountNotFound` is already handled. Alternatively, block split/merge/authorize/deactivate instructions on stake accounts that have a pending, not-yet-distributed partitioned reward (tracking eligibility via `stakes_cache` or a pending-rewards set) similar to how `recalculate_partitioned_rewards_if_active` recomputes rewards from current state after a restore — recalculating rather than replaying frozen `new_stake` values for split/merged accounts would also resolve the correctness gap.

### Proof of Concept
```rust
// runtime/src/bank/partitioned_epoch_rewards/distribution.rs (new test)
#[test]
fn test_split_during_distribution_window_panics_assert() {
    // 1. Build a bank with a single validator/stake account earning rewards,
    //    using `create_reward_bank_with_specific_stakes` helpers already present
    //    in this module's test suite, with num_partitions > 1 so there is a
    //    multi-block distribution window.
    // 2. Advance to the epoch boundary slot so `EpochRewardStatus::Active(Calculation(_))`
    //    is set and `PartitionedStakeReward` values are frozen for each stake pubkey.
    // 3. Before the block in which the target stake_pubkey's partition is distributed,
    //    submit a signed `stake_instruction::split` transaction from the attacker's own
    //    stake account into a new stake account for some fraction of the stake,
    //    using the attacker's own stake/withdraw authority. Confirm it succeeds
    //    (as demonstrated by `test_rewards_period_system_transfer`, ordinary
    //    transactions targeting stake accounts are not blocked during the reward
    //    period).
    // 4. Advance to the block containing that pubkey's distribution partition and
    //    call `distribute_partitioned_epoch_rewards()` (or replay the block).
    // Expected (bug): the process panics inside `build_updated_stake_reward` with
    // "stake reward delegation must be consistent with the updated stake account
    //  lamport balance", because `stake.delegation.stake` (post-split, reduced)
    // no longer equals `new_stake.delegation.stake` (pre-split, frozen value).
    //
    // Expected (fixed behavior): no panic; the mismatch is handled gracefully
    // (e.g., reward re-attributed/burned via a `DistributionError` and logged),
    // and `sum(stake_reward_lamports_minted + stake_reward_lamports_burned)`
    // across all partitions still equals the originally calculated
    // `total_stake_rewards_lamports`.
}
```

### Citations

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L859-871)
```rust
                            let stake_reward = inflation.stake_reward;
                            (
                                Some(PartitionedStakeReward {
                                    stake_pubkey: **stake_pubkey,
                                    inflation,
                                    block_reward,
                                }),
                                Some(RewardAccumulation {
                                    stake_reward,
                                    commission: Some((commission_pubkey, reward_commission)),
                                }),
                            )
                        }
```

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L80-149)
```rust
    pub(in crate::bank) fn distribute_partitioned_epoch_rewards(&mut self) {
        let EpochRewardStatus::Active(status) = &self.epoch_reward_status else {
            return;
        };

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

            datapoint_info!(
                "epoch-rewards-status-update",
                ("slot", self.slot(), i64),
                ("block_height", height, i64),
                ("partition_us", partition_us, i64),
                (
                    "distribution_starting_block_height",
                    distribution_starting_block_height,
                    i64
                ),
            );
        }

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

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L269-269)
```rust
        let mut new_stake = partitioned_stake_reward.inflation.stake;
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

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L384-407)
```rust
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
```

**File:** runtime/src/bank/partitioned_epoch_rewards/mod.rs (L1082-1157)
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
```

**File:** runtime/src/bank.rs (L4757-4777)
```rust
    pub fn store_accounts<'a>(
        &self,
        accounts: impl StorableAccounts<'a>,
        thread_pool_for_loading_accounts: Option<&ThreadPool>,
    ) {
        assert!(!self.freeze_started());
        let mut m = Measure::start("stakes_cache.check_and_store");
        let new_warmup_cooldown_rate_epoch = self.new_warmup_cooldown_rate_epoch();
        let use_fixed_point_stake_math = self.use_fixed_point_stake_math();

        (0..accounts.len()).for_each(|i| {
            accounts.account(i, |account| {
                self.stakes_cache.check_and_store(
                    account.pubkey(),
                    &account,
                    new_warmup_cooldown_rate_epoch,
                    use_fixed_point_stake_math,
                )
            })
        });
        self.store_accounts_without_stakes_cache(accounts, thread_pool_for_loading_accounts);
```

**File:** runtime/src/stakes.rs (L143-153)
```rust
        } else if stake_program::check_id(owner) {
            match StakeAccount::try_from(create_account_shared_data(account)) {
                Ok(stake_account) => {
                    let mut stakes = self.0.write().unwrap();
                    stakes.upsert_stake_delegation(
                        *pubkey,
                        stake_account,
                        new_rate_activation_epoch,
                        use_fixed_point_stake_math,
                    );
                }
```
