## Title
Attacker-recreated stake account at same pubkey between reward calculation and distribution can trigger a deterministic `assert_eq!` panic in `Bank::build_updated_stake_reward` - (`runtime/src/bank/partitioned_epoch_rewards/distribution.rs`)

## Summary
`Bank::build_updated_stake_reward` reads the *current* stake account for `partitioned_stake_reward.stake_pubkey` from the live `StakesCache` at distribution time and compares it against a reward value (`new_stake.delegation.stake`) that was computed earlier during `calculate_rewards_for_partitioning`. If the account's delegation state changes between these two phases — e.g. because the owner closes it via `StakeInstruction::Withdraw` and re-creates/re-delegates it at the same pubkey before the assigned distribution block — the consistency check `assert_eq!(expected_delegation, new_stake.delegation.stake, ...)` at [1](#0-0)  can fail. Because this is a hard `assert_eq!` (not a `Result::Err`), the mismatch panics the validator process rather than failing closed with `DistributionError`.

## Finding Description
`store_stake_accounts_in_partition` fetches the stakes-cache snapshot fresh, at the moment each distribution partition block executes, not the snapshot from calculation time: [2](#0-1) . It then calls `build_updated_stake_reward`, which looks up the account by `stake_pubkey` in that live cache: [3](#0-2) .

The reward amount itself (`partitioned_stake_reward.inflation.stake`) was computed earlier, during `calculate_rewards_for_partitioning`/`calculate_stake_rewards_and_commissions`, from a *stable, cached* stake-delegations snapshot taken at the epoch boundary: [4](#0-3) , [5](#0-4) . This result is cached (keyed by `parent_hash`) and reused across all distribution blocks for the epoch: [6](#0-5) .

Reward distribution across an epoch happens over multiple separate blocks: `distribute_partitioned_epoch_rewards` runs once per block, and for accounts hashed into partitions after the first, several blocks elapse between the epoch-boundary calculation block and the block that actually calls `store_stake_accounts_in_partition` for a given pubkey: [7](#0-6) . Normal user transactions, including stake-program instructions, continue to be processed in these intervening blocks — the test `test_rewards_period_system_transfer` explicitly documents that account state can be mutated "regardless of rewards period": [8](#0-7) . There is no code path found that blocks `StakeInstruction::Withdraw`/`Initialize`/`DelegateStake` while `EpochRewardStatus::Active`.

If the withdrawer of a stake account closes it (`Withdraw` to zero lamports) and then recreates a stake account at the exact same pubkey (requires controlling the underlying keypair, since `CreateAccount` needs the address's signature) with a different delegation amount before that pubkey's assigned distribution block, then at distribution time:
- `stake.delegation.stake` (read live) reflects the *new* delegation,
- `new_stake.delegation.stake` (from calculation phase) reflects `old_delegation.stake + stake_reward`.

Unless the new delegation happens to numerically equal the old one, `expected_delegation != new_stake.delegation.stake`, and the `assert_eq!` panics. Because all validators replaying the same block deterministically observe the same live stakes-cache state (it is derived from the same sequence of committed transactions), this panic is **not an isolated single-node crash** — every validator processing this slot hits the identical assertion failure, which is a deterministic, network-wide halt condition rather than silent data corruption.

The code comment at `store_stake_accounts_in_partition` even acknowledges the assumption being violated: "Because stake accounts are checked in calculation, and further state mutation prevents by stake-program restrictions, there should never be rewards burned" — [9](#0-8) . This assumption is incorrect when a stake account is closed and re-created at the same address between calculation and distribution: no "stake-program restriction" prevents `Withdraw` + `CreateAccount`/`Initialize`/`DelegateStake` at the same pubkey during the reward interval.

## Impact Explanation
This is not lamport theft (the account being manipulated belongs to the attacker/withdrawer themselves per the stated precondition, so there is no "victim" delegation being redirected) — the `expected_delegation`/`new_stake` mismatch simply causes `assert_eq!` to panic deterministically on all validators processing the distribution block for that pubkey. This matches the in-scope "epoch-boundary halt" impact category: a consensus-halting bug triggerable by an ordinary, unprivileged user issuing standard stake instructions they are authorized to sign, without any operator/gossip/leader control.

## Likelihood Explanation
Feasibility depends on:
1. The stake account's pubkey hashing into a distribution partition that is not the very first one (`hash_rewards_into_partitions`), giving the attacker at least one intervening block to submit `Withdraw`→`CreateAccount`/`Initialize`/`DelegateStake`. With multiple partitions typical for any non-trivial validator set, this is readily achievable, and an attacker can simply retry across epochs/accounts until their target pubkey lands in a later partition.
2. This assert path is only reached when `relax_post_exec_min_balance_check` (the `adjust_delegations_for_rent` feature) is *not* active — see [10](#0-9) ; on clusters where this feature has since activated, the vulnerable branch is unreachable and the code instead runs the rent-adjustment path, which has no such assert. This significantly narrows real-world exploitability to earlier feature-set configurations/clusters where the feature is inactive.
3. No signer/authority/rent checks in the reward-distribution path prevent this sequence; the only guard is the assert itself, which is the very thing that fails.

Given the feature-gating caveat, likelihood is conditional rather than universal, but the underlying code path lacks a fail-closed error return and instead panics — a latent correctness/robustness bug independent of whether it is presently reachable on a given cluster.

## Recommendation
Replace the `assert_eq!` in the non-`adjust_delegations_for_rent` branch of `build_updated_stake_reward` with a fallible check that returns `DistributionError` (e.g., a new `DistributionError::DelegationMismatch` variant) instead of panicking, mirroring how `AccountNotFound`/`ArithmeticOverflow`/`UnableToSetState` are already handled via `Result`. Additionally, consider snapshotting the exact `StakeStateV2` (not just recomputing from the live cache) used during calculation and validating that the live account is unchanged (e.g. by comparing lamports/state hash) before applying the reward, so unexpected close/recreate sequences fail the individual reward (burning it, as already logged) rather than aborting the whole block.

## Proof of Concept
```rust
// runtime/src/bank/partitioned_epoch_rewards/distribution.rs (test module)
//
// Goal: reproduce a stake-account close+recreate between
// calculate_rewards_for_partitioning and the distribution block that
// calls build_updated_stake_reward for that pubkey, and show the
// non-adjust_delegations_for_rent branch panics via assert_eq! instead
// of returning a DistributionError.
//
// 1. Build a RewardBank with `relax_post_exec_min_balance_check` feature
//    deactivated and enough stake accounts to require >1 distribution
//    partition (as in `create_reward_bank_with_specific_stakes`).
// 2. Advance to the epoch boundary bank; assert `is_calculated()` and
//    capture `epoch_reward_status` (Calculation phase) with the target
//    stake_pubkey's `PartitionedStakeReward` (old_delegation + reward).
// 3. Identify a stake_pubkey hashed into partition index > 0 via
//    `hash_rewards_into_partitions`.
// 4. In an intervening block before that pubkey's partition is reached:
//      - submit `stake_instruction::withdraw` signed by the withdrawer
//        to fully close the account (0 lamports),
//      - submit `system_instruction::create_account` for the same
//        pubkey (funded, owned by stake program),
//      - submit `stake_instruction::initialize` + `delegate_stake` with
//        a *different* stake amount than the original delegation.
// 5. Advance to the block matching that pubkey's assigned partition
//    index, invoking `store_stake_accounts_in_partition`.
// Expected (buggy) result: the process panics inside
// `Bank::build_updated_stake_reward`'s `assert_eq!` because
// `expected_delegation` (computed from the new live delegation + reward)
// differs from `new_stake.delegation.stake` (computed from the
// pre-recreation delegation + reward).
// Desired (fixed) result: `build_updated_stake_reward` returns
// `Err(DistributionError::DelegationMismatch)` (or similar), the reward
// is burned/logged as in the existing `Err` branch, and the block
// completes without panicking.
```

### Citations

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L78-149)
```rust
impl Bank {
    /// Process reward distribution for the block if it is inside reward interval.
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

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L270-294)
```rust
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

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L330-332)
```rust
    /// Because stake accounts are checked in calculation, and further state
    /// mutation prevents by stake-program restrictions, there should never be
    /// rewards burned.
```

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L361-365)
```rust
        let stakes_cache = self.stakes_cache.stakes();
        let stakes_cache_accounts = stakes_cache.stake_delegations();
        let stake_history = stakes_cache.history();
        let new_warmup_cooldown_rate_epoch = self.new_warmup_cooldown_rate_epoch();
        let rent = &self.rent_collector.rent;
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L329-346)
```rust
        let mut epoch_rewards_calculation_cache =
            self.epoch_rewards_calculation_cache.lock().unwrap();
        let rewards_calculation = epoch_rewards_calculation_cache
            .entry(self.parent_hash)
            .or_insert_with(|| {
                Arc::new(self.calculate_rewards_for_partitioning(
                    stake_history,
                    stake_delegations,
                    cached_vote_accounts,
                    rewarded_epoch,
                    reward_epoch_delegated_stakes,
                    reward_calc_tracer,
                    thread_pool,
                    metrics,
                ))
            })
            .clone();
        drop(epoch_rewards_calculation_cache);
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L470-482)
```rust
    /// Calculate rewards from previous epoch to prepare for partitioned distribution.
    pub(super) fn calculate_rewards_for_partitioning<'a>(
        &self,
        stake_history: &StakeHistory,
        stake_delegations: Vec<(&'a Pubkey, &'a StakeAccount<Delegation>)>,
        cached_vote_accounts: CachedVoteAccounts<'_>,
        rewarded_epoch: Epoch,
        reward_epoch_delegated_stakes: RewardEpochDelegatedStakes,
        reward_calc_tracer: Option<impl Fn(&RewardCalculationEvent) + Send + Sync>,
        thread_pool: &ThreadPool,
        metrics: &mut RewardsMetrics,
    ) -> PartitionedRewardsCalculation {
        let capitalization = self.capitalization();
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L813-849)
```rust
        let stake_delegations_len = stake_delegations.len();
        let mut stake_rewards = PartitionedStakeRewards::with_capacity(stake_delegations_len);
        let rewards_accumulator: RewardsAccumulator = thread_pool.install(|| {
            stake_delegations
                .par_iter()
                .zip(&mut stake_rewards.spare_capacity_mut()[..stake_delegations_len])
                .with_min_len(500)
                .filter_map(|((stake_pubkey, stake_account), reward_ref)| {
                    let block_reward = if block_revenue_sharing {
                        calculate_block_reward(
                            rewarded_epoch,
                            stake_account.delegation(),
                            stake_history,
                            cached_vote_accounts.distribution_epoch_vote_accounts,
                            ag_epoch_type,
                            new_warmup_cooldown_rate_epoch,
                            use_fixed_point_stake_math,
                        )
                    } else {
                        0
                    };
                    let maybe_reward_record = self.redeem_delegation_rewards(
                        rewarded_epoch,
                        stake_pubkey,
                        stake_account,
                        &point_value,
                        stake_history,
                        &cached_vote_accounts,
                        reward_calc_tracer.as_ref(),
                        new_warmup_cooldown_rate_epoch,
                        delay_commission_updates,
                        commission_rate_in_basis_points,
                        adjust_delegations_for_rent,
                        ag_epoch_type,
                        custom_commission_collector,
                        use_fixed_point_stake_math,
                    );
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
