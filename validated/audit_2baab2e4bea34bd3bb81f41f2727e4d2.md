### Title
`pending_delegator_rewards` is read and paid out every epoch but never decremented, allowing block rewards to be duplicated indefinitely - ([File: runtime/src/bank/partitioned_epoch_rewards/calculation.rs])

### Summary
This is the same bug class as the Mochi `claimRewardAsMochi` finding: a balance is read and paid out, but the code never reduces that balance afterwards, so the same value keeps getting re-paid. In agave's SIMD-0123 "block revenue sharing" reward path, `calculate_block_reward` reads a vote account's `pending_delegator_rewards` field and distributes a proportional share of it to every delegated stake account each epoch, but no code path subtracts the distributed amount from `pending_delegator_rewards` afterward.

### Finding Description
`deposit_delegator_rewards` lets anyone (the vote account does not even need to sign) transfer lamports into a vote account and increment its `pending_delegator_rewards` counter via `add_pending_delegator_rewards`: [1](#0-0) [2](#0-1) 

During epoch-reward calculation, `calculate_block_reward` reads this same field and computes each stake account's share of it: [3](#0-2) 

That value is placed into `PartitionedStakeReward.block_reward` for every stake delegation: [4](#0-3) 

and credited directly to each stake account's lamports balance at distribution time, and capitalization is bumped by the amount: [5](#0-4) [6](#0-5) 

Nowhere in `handler.rs`, `vote_state/mod.rs`, `vote_processor.rs`, `calculation.rs`, or `distribution.rs` is `pending_delegator_rewards` ever subtracted, reset, or otherwise reduced after being read for payout — the only mutator is `add_pending_delegator_rewards`, which only adds. Exhaustive `grep` for any subtraction/reset pattern on this field across the repo returned no matches outside of unit tests, which manually zero the field to simulate a "post-distribution" state rather than exercising real distribution code that clears it.

This mirrors the referral report exactly: `reward[msg.sender]` (Mochi) / `pending_delegator_rewards` (agave) is read to compute a payout and the payout is sent, but the balance backing it is never reduced, so the same balance is paid out again on the next iteration (epoch).

### Impact Explanation
Because `calculate_block_reward` re-reads the same un-decremented `pending_delegator_rewards` value every epoch, the same deposited amount gets distributed to stake accounts repeatedly, epoch after epoch, and each distribution increases `self.capitalization` by the (re-)distributed amount. This is a concrete minting of lamports / duplicated reward distribution: delegators to a vote account that once received a `DepositDelegatorRewards` deposit continue to be credited with block rewards derived from that stale deposit indefinitely, well beyond the single epoch the deposit was meant to fund, inflating total stake-account balances and total token supply beyond what was actually deposited.

### Likelihood Explanation
Likelihood is high once `block_revenue_sharing`, `commission_rate_in_basis_points`, and `custom_commission_collector` features are active (required for `DepositDelegatorRewards`/`calculate_block_reward` to run) — this is not a validator/operator-privileged path: `deposit_delegator_rewards` only requires the depositor to sign the system transfer, and reward calculation/distribution runs automatically every epoch for every bank without any special trigger, guaranteeing the stale value is re-read and re-paid on the very next epoch boundary.

### Recommendation
After `calculate_block_reward` determines the amount to distribute for an epoch (or immediately after distribution is finalized in `distribute_epoch_rewards_in_partition`/`store_stake_accounts_in_partition`), subtract the distributed portion from the vote account's `pending_delegator_rewards` field (e.g. add a `subtract_pending_delegator_rewards` method mirroring `add_pending_delegator_rewards`) and persist the updated vote account state, so the same balance cannot be redistributed on subsequent epochs.

### Proof of Concept
1. Call `VoteInstruction::DepositDelegatorRewards { deposit: X }` to set a vote account's `pending_delegator_rewards = X`, as exercised in `test_deposit_delegator_rewards`: [7](#0-6) 
2. Let an epoch boundary pass; `calculate_stake_rewards_and_commissions` → `calculate_block_reward` computes and distributes `block_reward` derived from `pending_delegator_rewards` to every stake account delegated to that vote account, and capitalization increases accordingly (`distribute_epoch_rewards_in_partition`).
3. Inspect the vote account state after distribution: `pending_delegator_rewards` is unchanged (still `X`), since no code path decrements it.
4. Let a second epoch boundary pass without any new deposit: `calculate_block_reward` reads the same `pending_delegator_rewards = X` again and distributes another full round of block rewards to the same stake accounts, again increasing capitalization — duplicating the reward from step 2 with no corresponding new deposit.

### Citations

**File:** programs/vote/src/vote_state/mod.rs (L974-987)
```rust
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

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L183-231)
```rust
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

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L192-198)
```rust
        // increase total capitalization by the distributed rewards
        self.capitalization
            .fetch_add(stake_reward_lamports_minted, Relaxed);

        // decrease total capitalization by burned block rewards
        self.capitalization
            .fetch_sub(block_reward_lamports_burned, Relaxed);
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

**File:** programs/vote/src/vote_processor.rs (L5120-5140)
```rust
        // Vote account should have been credited `deposit_amount`.
        // Source account should have been debited `deposit_amount`.
        // Vote state's `pending_delegator_rewards` should be updated.
        let vote_account_starting_lamports = vote_account_v4.lamports();
        let source_account_starting_lamports = source_lamports;
        let resulting_vote_account = &resulting_accounts[0];
        let resulting_source_account = &resulting_accounts[1];
        let vote_state =
            deserialize_vote_state_for_test(resulting_vote_account.data(), &vote_pubkey);
        assert_eq!(
            resulting_vote_account.lamports(),
            vote_account_starting_lamports + deposit_amount,
        );
        assert_eq!(
            resulting_source_account.lamports(),
            source_account_starting_lamports - deposit_amount,
        );
        assert_eq!(
            vote_state.as_ref_v4().pending_delegator_rewards,
            deposit_amount,
        );
```
