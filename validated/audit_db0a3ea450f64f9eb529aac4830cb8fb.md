### Title
`pending_delegator_rewards` is never decremented after being distributed, causing duplicated block-reward payouts and permanently frozen vote-account lamports - ([File: programs/vote/src/vote_state/mod.rs], [File: runtime/src/bank/partitioned_epoch_rewards/calculation.rs])

### Summary
`VoteStateV4::pending_delegator_rewards` is a bookkeeping field that (a) any unprivileged account can increase via the permissionless `DepositDelegatorRewards` vote instruction, (b) is read every epoch by the reward-distribution path to compute each staker's share of "block rewards" (SIMD-0123), and (c) is used by `withdraw()` to reserve a portion of the vote account's balance from being withdrawn. Across the whole codebase there is no code path that decrements this field after it has been consumed by the epoch reward calculation — it is only ever incremented.

### Finding Description
`deposit_delegator_rewards` transfers lamports from any signer into the vote account and increments the accounting field via `add_pending_delegator_rewards`: [1](#0-0) 

That accounting field is only ever mutated by `add_pending_delegator_rewards`, which performs a `checked_add` and nothing else: [2](#0-1) 

Every epoch, `calculate_block_reward` reads the *current* value of `pending_delegator_rewards` from the vote account and computes each stake account's proportional share, which is then paid out as `block_reward` lamports added directly to the stake account during distribution: [3](#0-2) [4](#0-3) [5](#0-4) 

Nowhere in `programs/vote/`, `runtime/src/bank/partitioned_epoch_rewards/`, or `runtime/src/inflation_rewards/` is `pending_delegator_rewards` ever subtracted, zeroed, or otherwise reduced in production logic (the only `= 0` assignments found are manual test fixtures that directly poke the serialized vote state, not runtime code).

Separately, `withdraw()` treats the full, never-decreasing `pending_delegator_rewards` as a permanent floor that must remain in the vote account balance and blocks closing the account while it is nonzero: [6](#0-5) 

This is the same bug class as the reported EigenPod issue: a privileged/expected update path (there, `CasimirManager::withdrawRewards`; here, the epoch-boundary consumption of `pending_delegator_rewards` in `calculate_block_reward`) is supposed to retire the accounting value once it has been "spent," but the retirement step doesn't exist, so the underlying value keeps being reused as if it were still fully available.

### Impact Explanation
Because `pending_delegator_rewards` is never decremented after distribution:
- The identical deposited amount is treated as fully available again in every subsequent epoch that the validator earns block-revenue-sharing credits, so the same pool of lamports keeps being redistributed to stakers epoch after epoch instead of once — a duplicated/misattributed reward payout each epoch.
- The withdraw-authority of the vote account can never fully reclaim the lamports below the `pending_delegator_rewards` floor, nor close the account while any deposit remains, effectively freezing those funds in the vote account permanently — `withdraw()` will keep returning `InstructionError::InsufficientFunds` for the reserved amount, and the full close path is blocked as long as `pending_delegator_rewards > 0`.

Both effects (duplicated rewards and permanently frozen lamports) are impact categories explicitly in scope.

### Likelihood Explanation
`DepositDelegatorRewards` is unauthenticated with respect to *who* may deposit — any account that can sign a system transfer can call it (only the source of the transfer must sign), as shown in the instruction's account requirements and tests. Once SIMD-0123/SIMD-0291/SIMD-0232/block-revenue-sharing features are active (which is required for this reward path to exist at all), any single deposit will be redistributed repeatedly for as long as the validator is active and earning block-revenue-share, with no additional action required from anyone. This is a deterministic consequence of normal operation, not a crafted edge case.

### Recommendation
After a stake account's proportional share of `pending_delegator_rewards` is computed and committed during partitioned epoch-reward distribution, subtract the distributed `block_reward` total for that vote account from `pending_delegator_rewards` in the same distribution step (mirroring how `stake.credits_observed`/`delegation.stake` are updated in `build_updated_stake_reward`). This retirement must be durable/idempotent across the calculation and distribution phases (including `recalculate_partitioned_rewards_if_active`) so a deposit is only ever paid out once, and the withdraw floor in `withdraw()` accurately reflects only truly-undistributed pending rewards.

### Proof of Concept
1. Activate `commission_rate_in_basis_points`, `custom_commission_collector`, and `block_revenue_sharing` features and create a V4 vote account with active stake delegated to it.
2. Any account calls `VoteInstruction::DepositDelegatorRewards { deposit: X }` (per `deposit_delegator_rewards`), which transfers `X` lamports into the vote account and sets `pending_delegator_rewards = X` via `add_pending_delegator_rewards`.
3. At the next epoch boundary, `calculate_block_reward` reads `pending_delegator_rewards = X` and pays out `X` (proportionally split by stake) to the delegated stake accounts as `block_reward`, per `calculate_stake_rewards_and_commissions`.
4. Because nothing decrements `pending_delegator_rewards`, at the following epoch boundary `calculate_block_reward` again reads `pending_delegator_rewards = X` (unchanged) and pays out the same `X` again to stakers — this repeats every epoch indefinitely.
5. Simultaneously, `withdraw()` continues to enforce `min_balance = rent_exempt + X` forever, so the withdraw authority can never fully withdraw or close the vote account even though the deposited lamports have already been "spent" via distribution.

### Citations

**File:** programs/vote/src/vote_state/mod.rs (L935-988)
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
}
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

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L820-833)
```rust
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
```

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L262-267)
```rust
        account
            .checked_add_lamports(partitioned_stake_reward.inflation.stake_reward)
            .map_err(|_| DistributionError::ArithmeticOverflow)?;
        account
            .checked_add_lamports(partitioned_stake_reward.block_reward)
            .map_err(|_| DistributionError::ArithmeticOverflow)?;
```
