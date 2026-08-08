### Title
Vote account `pending_delegator_rewards` is never decremented after block-reward distribution, permanently freezing funds behind the withdraw reserve - (File: `programs/vote/src/vote_state/mod.rs`, `runtime/src/bank/partitioned_epoch_rewards/calculation.rs`, `runtime/src/bank/partitioned_epoch_rewards/distribution.rs`)

### Summary
`VoteStateV4::pending_delegator_rewards` (SIMD-0123) is used both as (1) a mandatory reserve that the `Withdraw` instruction refuses to let the authorized withdrawer touch, and (2) as the numerator used to compute each staker's share of the vote account's "block reward" at epoch-reward distribution time. The only mutator of this field found in the reachable code is `add_pending_delegator_rewards`, called from `deposit_delegator_rewards`; no code path was found that decrements/clears `pending_delegator_rewards` on the vote account after `calculate_block_reward` mints/distributes the corresponding lamports to delegators' stake accounts. This mirrors the reported bug class: a value representing an obligation/allocation is set but never cleared when the corresponding "claim"/distribution happens, so lamports become permanently locked behind that value's check.

### Finding Description
`deposit_delegator_rewards` transfers lamports into the vote account and increases `pending_delegator_rewards` via `add_pending_delegator_rewards`, which is a pure `checked_add`: [1](#0-0) [2](#0-1) 

`withdraw()` treats `pending_delegator_rewards` as an untouchable reserve: it blocks full account closure while it is `> 0`, and for partial withdrawals it enforces `min_balance = rent_exempt + pending_delegator_rewards`: [3](#0-2) 

Separately, during epoch-reward calculation, `calculate_block_reward` reads the vote account's `pending_delegator_rewards` and computes each stake account's proportional share of it (`pending_delegator_rewards * stake / total_active_stake`, clamped to `pending_delegator_rewards`): [4](#0-3) 

That computed `block_reward` is then credited directly onto the staker's stake account lamports during partitioned distribution via `build_updated_stake_reward`, and the bank's total `capitalization` is separately adjusted for `block_reward_lamports_distributed`/`burned` — there is no lamport debit from the vote account and no corresponding decrement of `pending_delegator_rewards` on the vote account itself: [5](#0-4) [6](#0-5) 

The result is analogous to the reported `blacklistProtocol()` bug: an accounting field that represents "funds owed"/"allocation" (there, `currentAllocations`; here, `pending_delegator_rewards`) is used to gate access to funds (there, blocking claim before zeroing allocation; here, reserving lamports in `withdraw()`), but the code path that is supposed to "settle" the obligation (there, `claimTokens`; here, the epoch block-reward distribution that pays stakers their share) never clears/reduces the gating value on the source account. Every epoch that block-revenue-sharing runs, stakers can be paid out based on the full `pending_delegator_rewards` amount again and again (since it is never reduced), while the authorized withdrawer of the vote account can never withdraw the lamports reserved by that same never-shrinking field — the reserved lamports are permanently frozen behind the `withdraw()` `min_balance` check.

### Impact Explanation
If `pending_delegator_rewards` is only ever increased and never decremented on the vote account, two connected consequences follow, both matching the "concrete... permanently frozen accounts" and "misattributed or duplicated rewards" acceptance criteria:
1. Lamports reserved by `pending_delegator_rewards` become permanently unwithdrawable by the authorized withdrawer (`InstructionError::InsufficientFunds` forever), i.e. frozen funds in the vote account, exactly like the LP funds frozen in the blacklisted protocol in the report.
2. Because `calculate_block_reward` recomputes stakers' shares from the same un-decremented `pending_delegator_rewards` value every reward epoch, stakers could receive the same reward pool credited repeatedly across epochs, which is a duplicated/misattributed reward distribution.

### Likelihood Explanation
This triggers under normal, unprivileged operation whenever `deposit_delegator_rewards` (SIMD-0123) is used and `block_revenue_sharing` (also gated behind SIMD-0123) is active, requiring no attacker privilege — any authorized withdrawer or delegator interacting with a v4 vote account under the standard reward-distribution flow would be affected once the feature is active.

### Recommendation
Confirm whether `pending_delegator_rewards` is decremented anywhere in the distribution path that was not indexed/visible in this review (e.g., inside `distribute_epoch_rewards_in_partition`, `store_stake_accounts_in_partition`, or a follow-up vote-account state update). If no such decrement exists, add logic to debit the distributed `block_reward` amount from the vote account's lamports and subtract it from `pending_delegator_rewards` as part of `store_stake_accounts_in_partition`/`build_updated_stake_reward`, so the reserve enforced by `withdraw()` shrinks in lockstep with actual distribution, preventing both permanent fund freezing and duplicate reward attribution.

### Proof of Concept
Not independently reproducible from the indexed code alone; conceptually:
1. Authorized party calls `DepositDelegatorRewards` to set `pending_delegator_rewards = X` on a v4 vote account (`programs/vote/src/vote_state/mod.rs:935-987`).
2. `block_revenue_sharing` is active; at the next epoch boundary, `calculate_block_reward` computes and distributes `X`-derived rewards to delegators' stake accounts (`runtime/.../calculation.rs:173-232`, `runtime/.../distribution.rs:239-297`).
3. Inspect the vote account post-distribution: `pending_delegator_rewards` is unchanged (still `X`), and the vote account's lamports are unchanged (no debit performed).
4. Authorized withdrawer attempts `Withdraw` for the full vote-account balance: `withdraw()` still rejects it because `pending_delegator_rewards > 0` (`programs/vote/src/vote_state/mod.rs:1084-1122`), freezing those lamports indefinitely, even though the reward they "back" may have already been paid out to stakers.

Given the scope of the indexed codebase, I was not able to confirm the complete absence of an out-of-view decrement step; this should be verified directly against the full source before treating this as conclusively confirmed.

### Citations

**File:** programs/vote/src/vote_state/mod.rs (L935-987)
```rust
/// Deposit delegator rewards into a vote account (SIMD-0123).
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
```

**File:** programs/vote/src/vote_state/mod.rs (L1084-1122)
```rust
    // Always zero until SIMD-0123 is activated.
    let pending_delegator_rewards = vote_state.pending_delegator_rewards();

    if remaining_balance == 0 {
        // SIMD-0123: vote account cannot be closed if
        // pending_delegator_rewards > 0.
        if pending_delegator_rewards > 0 {
            return Err(InstructionError::InsufficientFunds);
        }

        let reject_active_vote_account_close = vote_state
            .epoch_credits()
            .last()
            .map(|(last_epoch_with_credits, _, _)| {
                let current_epoch = clock.epoch;
                // if current_epoch - last_epoch_with_credits < 2 then the validator has received credits
                // either in the current epoch or the previous epoch. If it's >= 2 then it has been at least
                // one full epoch since the validator has received credits.
                current_epoch.saturating_sub(*last_epoch_with_credits) < 2
            })
            .unwrap_or(false);

        if reject_active_vote_account_close {
            return Err(VoteError::ActiveVoteAccountClose.into());
        } else {
            // Deinitialize upon zero-balance
            VoteStateHandler::deinitialize_vote_account_state(&mut vote_account, target_version)?;
        }
    } else {
        // SIMD-0123: withdrawable balance when pending_delegator_rewards > 0
        // is lamports - pending_delegator_rewards - rent_exempt_minimum.
        let min_rent_exempt_balance = rent_sysvar.minimum_balance(vote_account.get_data().len());
        let min_balance = min_rent_exempt_balance
            .checked_add(pending_delegator_rewards)
            .ok_or(InstructionError::ArithmeticOverflow)?;
        if remaining_balance < min_balance {
            return Err(InstructionError::InsufficientFunds);
        }
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

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L173-232)
```rust
/// Calculates block reward for a stake account based on SIMD-0123
fn calculate_block_reward(
    rewarded_epoch: Epoch,
    delegation: &Delegation,
    stake_history: &StakeHistory,
    distribution_epoch_vote_accounts: &VoteAccounts,
    ag_epoch_type: &AlpenglowEpochType,
    new_warmup_cooldown_rate_epoch: Option<Epoch>,
    use_fixed_point_stake_math: bool,
) -> u64 {
    let vote_pubkey = delegation.voter_pubkey;
    let Some(vote_account) = distribution_epoch_vote_accounts.get(&vote_pubkey) else {
        debug!("could not find vote account {vote_pubkey} in cache");
        return 0;
    };
    let vote_state = vote_account.vote_state_view();
    let pending_delegator_rewards = vote_state.pending_delegator_rewards();
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
        0
    } else {
        let stake = delegation_effective_stake(
            delegation,
            rewarded_epoch,
            stake_history,
            new_warmup_cooldown_rate_epoch,
            use_fixed_point_stake_math,
        );
        // During recalculation, if stake account has already received rewards,
        // it's possible to have `stake > total_active_stake`. If
        // `pending_delegator_rewards` is a huge number, we could potentially
        // overflow a `u64`. We can also have individual rewards look greater
        // than the pending rewards. This is harmless in practice, but we
        // clamp it just to be safe
        (pending_delegator_rewards as u128 * stake as u128 / total_active_stake as u128)
            .try_into()
            .unwrap_or(u64::MAX)
            .min(pending_delegator_rewards)
    }
}
```

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L173-223)
```rust
    /// Process reward credits for a partition of rewards
    /// Store the rewards to AccountsDB, update reward history record and total capitalization.
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
```

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L239-297)
```rust
    fn build_updated_stake_reward(
        distribution_epoch: u64,
        stake_history: &StakeHistory,
        new_warmup_cooldown_rate_epoch: Option<Epoch>,
        stakes_cache_accounts: &imbl::HashMap<Pubkey, StakeAccount<Delegation>>,
        partitioned_stake_reward: &PartitionedStakeReward,
        rent: &Rent,
        adjust_delegations_for_rent: bool,
        use_fixed_point_stake_math: bool,
    ) -> Result<StakeReward, DistributionError> {
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
        account
            .set_state(&StakeStateV2::Stake(meta, new_stake, flags))
            .map_err(|_| DistributionError::UnableToSetState)?;
```
