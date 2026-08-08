Based on my research, I found a plausible analog in agave's Alpenglow block-reward calculation, though I was unable to fully verify one aspect (noted below) due to exhausted tool budget.

### Title
Alpenglow block-reward recalculation reads live, mutable `pending_delegator_rewards` instead of a value frozen at the reward epoch boundary, causing inconsistent reward allocation across a single distribution - (File: `runtime/src/bank/partitioned_epoch_rewards/calculation.rs`)

### Summary
`calculate_block_reward` computes a stake account's share of a vote account's `pending_delegator_rewards` pool for a given rewarded epoch. This value is not fixed at the time the reward calculation is first performed; it is re-read from the live vote account any time the calculation is redone (e.g. via `recalculate_stake_rewards` on snapshot restore). Because `pending_delegator_rewards` can be increased at any time by any signer through the permissionless `DepositDelegatorRewards` instruction, the block-reward pool used to compute rewards for the *same* rewarded epoch can differ between the original partitioning calculation and any later recalculation of the still-undistributed partitions — exactly analogous to the reported Ion Protocol bug where `_accrueFee` used a live, unpaused view of `pool.getUnderlyingClaimOf` instead of a value that should have been frozen for a period, corrupting per-recipient accounting.

### Finding Description
`calculate_block_reward` reads the reward pool directly from the current vote account state: [1](#0-0) 

The surrounding code explicitly acknowledges that `distribution_epoch_vote_accounts` reflects *live, post-calculation* state and therefore cannot be trusted for values that must remain fixed for the rewarded epoch — this is why `total_active_stake` is deliberately taken from a frozen `RewardEpochDelegatedStakes` snapshot instead of the live vote/stake accounts: [2](#0-1) 

However, this same frozen-snapshot treatment is not applied to `pending_delegator_rewards` — it is read straight from the live `vote_state` on every invocation of `calculate_block_reward`, whether during the original per-epoch-boundary calculation (`calculate_rewards_for_partitioning` → `calculate_stake_rewards_and_commissions`) or during `recalculate_stake_rewards`, which is invoked by `initialize_after_snapshot_restore` whenever a bank is rebuilt from a snapshot while an `EpochRewardStatus::Active` distribution is in progress: [3](#0-2) [4](#0-3) 

`pending_delegator_rewards` can be increased at any time by an unprivileged, permissionless instruction, `DepositDelegatorRewards`, requiring only that the sender sign the lamport transfer: [5](#0-4) [6](#0-5) [7](#0-6) 

Epoch reward distribution for stake accounts is spread over multiple blocks (up to ~10% of an epoch's slots), so there is a real window during which such a deposit could land between the original calculation of `block_reward` for a partition and a later recalculation of the still-unpaid partitions: [8](#0-7) 

The test suite explicitly documents the maintainers' awareness of exactly this class of bug (using the wrong, unfrozen denominator on recalculation) for the `total_active_stake` term, but the fix (`RewardEpochDelegatedStakes`) was scoped only to the denominator, not to the `pending_delegator_rewards` numerator: [9](#0-8) 

### Impact Explanation
Because a stake account's block reward is `pending_delegator_rewards * stake / total_active_stake` (clamped to `pending_delegator_rewards`), an increase in the live `pending_delegator_rewards` between the initial calculation and a later recalculation means stake accounts whose reward is computed later in the same distribution (post-recalculation) receive a disproportionately larger share of the pool than accounts already paid from the earlier, smaller value — for rewards nominally belonging to the same rewarded epoch. This breaks the intended proportional allocation of `pending_delegator_rewards` across delegators for that epoch and can result in some stake accounts receiving inflated block-reward payouts relative to what the original epoch-boundary calculation intended, i.e., a form of misattributed/duplicated reward accounting analogous to the reported Ion Protocol issue.

Note: I was not able to fully verify within the remaining research budget whether `pending_delegator_rewards` is deducted from the vote account when `block_reward` is paid out (that logic, if present, likely lives in `distribute_reward_commissions` in the same file, which I could not fully inspect). This determines whether the impact is "some delegators get more than their fair share of a fixed pool" (accounting/fairness bug) versus "net new lamports minted beyond the pool" (more severe). This should be verified by a background agent before finalizing severity.

### Likelihood Explanation
Reachability requires: (1) an Alpenglow-active vote account whose reward distribution spans multiple blocks (common, since large stake sets are chunked across up to 10% of an epoch's slots), and (2) either an `initialize_after_snapshot_restore` occurring mid-distribution (validator restart/bootstrap from snapshot) or another code path that calls `recalculate_partitioned_rewards_if_active`, combined with a `DepositDelegatorRewards` transaction landing between the original calculation and the recalculation. `DepositDelegatorRewards` is a normal permissionless instruction with no special privilege requirement, so likelihood is Medium — it depends on timing but does not require any privileged actor.

### Recommendation
Freeze `pending_delegator_rewards` for the rewarded epoch the same way `total_active_stake` is frozen via `RewardEpochDelegatedStakes` — i.e., snapshot the value at the original `calculate_rewards_for_partitioning` call and thread it through to any later `recalculate_stake_rewards` call, instead of re-reading it from the live vote account on every recalculation.

### Proof of Concept
1. Enable Alpenglow / block revenue sharing, and set up a vote account with many delegators such that `get_reward_distribution_num_blocks` produces multiple distribution partitions.
2. At epoch boundary, `begin_partitioned_rewards` computes `block_reward` for all stake accounts using `pending_delegator_rewards = X` (see `calculate_block_reward`, `runtime/src/bank/partitioned_epoch_rewards/calculation.rs:173-232`), and distributes the first partition(s).
3. Before all partitions are distributed, submit a `DepositDelegatorRewards` transaction that increases the vote account's `pending_delegator_rewards` to `X + Y` (`programs/vote/src/vote_state/mod.rs:936-988`).
4. Trigger `initialize_after_snapshot_restore` (e.g., validator restart from a snapshot taken after the deposit but before full distribution completes), which calls `recalculate_partitioned_rewards_if_active` → `recalculate_stake_rewards` → `calculate_block_reward`, now reading `pending_delegator_rewards = X + Y` (`runtime/src/bank/partitioned_epoch_rewards/calculation.rs:1011-1094`).
5. Observe that stake accounts in the remaining, not-yet-distributed partitions receive block rewards computed against `X + Y`, while accounts already paid in earlier partitions received rewards computed against `X`, for the same nominal rewarded epoch and the same `total_active_stake` denominator — demonstrating inconsistent/incorrect per-recipient reward accounting for a single epoch's distribution.

### Citations

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L183-189)
```rust
    let vote_pubkey = delegation.voter_pubkey;
    let Some(vote_account) = distribution_epoch_vote_accounts.get(&vote_pubkey) else {
        debug!("could not find vote account {vote_pubkey} in cache");
        return 0;
    };
    let vote_state = vote_account.vote_state_view();
    let pending_delegator_rewards = vote_state.pending_delegator_rewards();
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L190-211)
```rust
    // NOTE: during recalculation, `distribution_epoch_vote_accounts` already
    // includes updated stake activation values from after the new epoch
    // calculation, so we need to use `RewardEpochDelegatedStakes` for the exact
    // values at the end of the reward epoch.
    let (AlpenglowEpochType::Alpenglow {
        reward_epoch_delegated_stakes,
        ..
    }
    | AlpenglowEpochType::MigrationEpoch {
        reward_epoch_delegated_stakes,
        ..
    }) = ag_epoch_type
    else {
        debug!("Alpenglow must be enabled for block reward calculation");
        return 0;
    };
    let total_active_stake = reward_epoch_delegated_stakes
        .delegated_stakes
        .get(&vote_pubkey)
        .copied()
        .unwrap_or(0);
    if total_active_stake == 0 {
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L1011-1033)
```rust
    /// If rewards are still active, recalculates partitioned stake rewards and
    /// updates Bank::epoch_reward_status. This method assumes that reward
    /// commissions have already been calculated and delivered, and *only*
    /// recalculates stake rewards
    pub(in crate::bank) fn recalculate_partitioned_rewards_if_active<F, TP>(
        &mut self,
        thread_pool_builder: F,
    ) where
        F: FnOnce() -> TP,
        TP: std::borrow::Borrow<ThreadPool>,
    {
        let epoch_rewards_sysvar = self.get_epoch_rewards_sysvar();
        if epoch_rewards_sysvar.active {
            let thread_pool = thread_pool_builder();
            let (stake_rewards, partition_indices) =
                self.recalculate_stake_rewards(&epoch_rewards_sysvar, thread_pool.borrow());
            self.set_epoch_reward_status_distribution(
                epoch_rewards_sysvar.distribution_starting_block_height,
                stake_rewards,
                partition_indices,
            );
        }
    }
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L2677-2797)
```rust
    #[test]
    fn test_recalculate_alpenglow_rewards_after_partial_distribution_uses_original_denominator() {
        let stake_lamports = 2_000_000_000;
        let validator_keypairs = vec![genesis_utils::ValidatorVoteKeypairs::new_rand()];
        let GenesisConfigInfo {
            mut genesis_config, ..
        } = genesis_utils::create_genesis_config_with_alpenglow_vote_accounts(
            1_000_000_000 * LAMPORTS_PER_SOL,
            &validator_keypairs,
            vec![stake_lamports],
        );
        genesis_config.epoch_schedule = EpochSchedule::new(SLOTS_PER_EPOCH);
        let features_to_deactivate = crate::slot_params::slot_time_feature_ids().to_vec();
        deactivate_features(&mut genesis_config, &features_to_deactivate);

        let mut accounts_db_config: AccountsDbConfig = ACCOUNTS_DB_CONFIG_FOR_TESTING;
        accounts_db_config.partitioned_epoch_rewards_config =
            PartitionedEpochRewardsConfig::new_for_test(1);
        let bank = Bank::new_from_genesis(
            &genesis_config,
            Arc::new(RuntimeConfig::default()),
            Vec::new(),
            None,
            accounts_db_config,
            None,
            None,
            Arc::default(),
            None,
            None,
        );

        let vote_pubkey = validator_keypairs[0].vote_keypair.pubkey();
        let vote_account = bank.get_account(&vote_pubkey).unwrap();
        let extra_stake_pubkey = Pubkey::new_unique();
        let extra_stake_account = stake_utils::create_stake_account(
            &extra_stake_pubkey,
            &vote_pubkey,
            &vote_account,
            &bank.rent_collector.rent,
            stake_lamports,
        );
        bank.store_account_and_update_capitalization(&extra_stake_pubkey, &extra_stake_account);

        let (bank, bank_forks) = bank.wrap_with_bank_forks_for_tests();
        let bank = Bank::new_from_parent_with_bank_forks(
            bank_forks.as_ref(),
            bank,
            SlotLeader::default(),
            SLOTS_PER_EPOCH,
        );
        assert_eq!(bank.epoch(), 1);

        let mut vote_account = bank.get_account(&vote_pubkey).unwrap();
        let VoteStateVersions::V4(mut vote_state) = vote_account
            .deserialize_data::<VoteStateVersions>()
            .unwrap()
        else {
            panic!("unexpected vote state version");
        };
        let last_credits = vote_state
            .epoch_credits
            .last()
            .map(|(_epoch, final_credits, _initial_credits)| *final_credits)
            .unwrap_or_default();
        vote_state
            .epoch_credits
            .push((bank.epoch(), last_credits + 1_000_000, last_credits));
        vote_account
            .serialize_data(&VoteStateVersions::V4(vote_state))
            .unwrap();
        bank.store_account(&vote_pubkey, &vote_account);

        let thread_pool = ThreadPoolBuilder::new().num_threads(1).build().unwrap();
        let mut bank = Bank::new_from_parent(
            bank,
            SlotLeader::default(),
            SLOTS_PER_EPOCH.saturating_mul(2),
        );
        assert_eq!(bank.epoch(), 2);

        let EpochRewardStatus::Active(EpochRewardPhase::Calculation(calculation_status)) =
            bank.epoch_reward_status.clone()
        else {
            panic!("{:?} not active calculation", bank.epoch_reward_status);
        };
        let original_stake_rewards = calculation_status.all_stake_rewards;
        let original_rewards = original_stake_rewards
            .enumerated_rewards_iter()
            .collect::<Vec<_>>();
        assert_eq!(original_rewards.len(), 2);
        let (paid_index, paid_reward) = original_rewards[0];
        let (unpaid_index, unpaid_reward) = original_rewards[1];
        assert!(paid_reward.inflation.stake_reward > 0);
        assert!(unpaid_reward.inflation.stake_reward > 0);

        // Force exactly one stake reward to be distributed before simulating
        // snapshot restore. That write updates StakesCache with a larger
        // delegation for the same vote account.
        bank.set_epoch_reward_status_distribution(
            bank.block_height(),
            Arc::clone(&original_stake_rewards),
            vec![vec![paid_index], vec![unpaid_index]],
        );
        bank.distribute_partitioned_epoch_rewards();

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

**File:** runtime/src/bank.rs (L6061-6081)
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

**File:** programs/vote/src/vote_processor.rs (L409-425)
```rust
        VoteInstruction::DepositDelegatorRewards { deposit } => {
            // SIMD-0123: Deposit delegator rewards.
            // Requires:
            // * SIMD-0185: Vote State V4
            // * SIMD-0291: Commission in Basis Points
            // * SIMD-0232: Custom Commission Collector
            let feature_set = invoke_context.get_feature_set();
            if !feature_set.commission_rate_in_basis_points
                || !feature_set.custom_commission_collector
                || !feature_set.block_revenue_sharing
            {
                return Err(InstructionError::InvalidInstructionData);
            }

            instruction_context.check_number_of_instruction_accounts(2)?;
            drop(me);
            vote_state::deposit_delegator_rewards(invoke_context, 0, 1, deposit, &signers)
```

**File:** programs/vote/src/vote_state/mod.rs (L936-988)
```rust
pub fn deposit_delegator_rewards<S: std::hash::BuildHasher>(
    invoke_context: &mut InvokeContext,
    vote_account_index: IndexOfAccount,
    sender_account_index: IndexOfAccount,
    deposit: u64,
    signers: &HashSet<Pubkey, S>,
) -> Result<(), InstructionError> {
    let transaction_context = &invoke_context.transaction_context;
    let instruction_context = transaction_context.get_current_instruction_context()?;

    let vote_address = *instruction_context.get_key_of_instruction_account(vote_account_index)?;
    let source_address =
        *instruction_context.get_key_of_instruction_account(sender_account_index)?;

    // Source account must sign the transfer.
    verify_authorized_signer(&source_address, signers)?;

    // SIMD-0123 states we must validate the vote account deserializes to a v4
    // *before* attempting CPI, then update the `pending_delegator_rewards`
    // field *last*.
    // We can deserialize it, and hold onto the deserialized payload in-memory.
    // This way, we can drop the account borrow but avoid re-deserializing
    // later, since we know only lamports will change.
    let mut vote_state = {
        let vote_account =
            instruction_context.try_borrow_instruction_account(vote_account_index)?;

        // Can't use `get_vote_state_handler_checked`, since it will convert
        // the underlying vote state to v4.
        // SIMD-0123 requires an *initialized v4*.
        let versioned = VoteStateVersions::deserialize(vote_account.get_data())?;
        if let VoteStateVersions::V4(vote_state_v4) = versioned {
            Ok(VoteStateHandler::new_v4(*vote_state_v4))
        } else {
            Err(InstructionError::InvalidAccountData)
        }
    }?;

    // CPI to System: Transfer from sender to vote account.
    invoke_context.native_invoke_signed(
        system_instruction::transfer(&source_address, &vote_address, deposit),
        &[],
    )?;

    // Update `pending_delegator_rewards`.
    let transaction_context = &invoke_context.transaction_context;
    let instruction_context = transaction_context.get_current_instruction_context()?;
    let mut vote_account =
        instruction_context.try_borrow_instruction_account(vote_account_index)?;

    vote_state.add_pending_delegator_rewards(deposit)?;
    vote_state.set_vote_account_state(&mut vote_account)
}
```

**File:** programs/vote/src/vote_state/handler.rs (L196-209)
```rust
    pub(crate) fn add_pending_delegator_rewards(
        &mut self,
        amount: u64,
    ) -> Result<(), InstructionError> {
        match &mut self.target_state {
            TargetVoteState::V4(v4) => {
                v4.pending_delegator_rewards = v4
                    .pending_delegator_rewards
                    .checked_add(amount)
                    .ok_or(InstructionError::ArithmeticOverflow)?;
                Ok(())
            }
        }
    }
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
