### Title
Vote program never decrements `pending_delegator_rewards` after block rewards are distributed, causing duplicated stake-reward payouts - ([File: programs/vote/src/vote_state/handler.rs])

### Summary
The vote-account field `pending_delegator_rewards` (SIMD-0123 block-reward escrow) is only ever incremented via `add_pending_delegator_rewards`, and is read every epoch by `calculate_block_reward` to compute stake rewards, but nowhere is it decremented or reset after those rewards are actually paid out to delegators' stake accounts. This mirrors the DODO H-7 pattern: an internal balance/accounting record (`pending_delegator_rewards`) is not updated to reflect value that has already been transferred out (paid to stakers), so the stale record is reused in the next accounting cycle.

### Finding Description
`deposit_delegator_rewards` deposits lamports into the vote account (via CPI transfer) and records the amount owed to delegators by calling `VoteStateHandler::add_pending_delegator_rewards`: [1](#0-0) 

The only mutator for this field is additive: [2](#0-1) 

Each epoch, `calculate_block_reward` reads `vote_state.pending_delegator_rewards()` directly from the vote account snapshot and computes each delegating stake account's proportional share, capped at the total `pending_delegator_rewards` value: [3](#0-2) 

That per-stake `block_reward` is then credited directly to the stake account via `checked_add_lamports` during distribution, and the produced `StakeReward` is stored: [4](#0-3) 

Nowhere in `redeem_delegation_rewards`, `calculate_stake_rewards_and_commissions`, `build_updated_stake_reward`, or `store_stake_accounts_in_partition` is the vote account's `pending_delegator_rewards` field decremented or the vote account itself re-stored with an updated (reduced) `pending_delegator_rewards` value to reflect the block reward that was just paid out. The only setter, `add_pending_delegator_rewards`, is additive-only; no corresponding subtract/consume method exists in `VoteStateHandler`.

### Impact Explanation
Because `pending_delegator_rewards` is never reduced after being used as the basis for a block-reward distribution, the same escrowed amount can be recomputed and redistributed to stake accounts in a subsequent epoch's reward calculation (`calculate_block_reward` reads the same un-decremented value again). This causes duplicated/misattributed reward issuance to stakers beyond what was actually deposited/owed, directly matching the "misattributed or duplicated rewards" impact category, and can also permit repeated minting of stake-reward lamports disproportionate to actual vote-account deposits, affecting cluster-wide reward accounting and capitalization correctness.

### Likelihood Explanation
This triggers automatically on the ordinary reward-distribution path (`calculate_block_reward` → `calculate_stake_rewards_and_commissions` → `store_stake_accounts_in_partition`) for any validator using SIMD-0123 block-revenue sharing with `block_revenue_sharing` enabled and any non-zero `pending_delegator_rewards`, i.e., any validator that has ever called `deposit_delegator_rewards`. No privileged or adversarial actor role is required — it is a systemic accounting gap in the reward-distribution and stake-accounting path.

### Recommendation
After computing and applying `block_reward` for a vote account's delegators in a given epoch, subtract the total distributed `block_reward` amount from that vote account's `pending_delegator_rewards` (analogous to calling `updateReserveByVault` after the transfer in the referenced report), persisting the updated vote account state so subsequent epochs do not re-use the already-paid-out escrow balance.

### Proof of Concept
Not independently executed/confirmed against a running validator due to tool/time constraints; the analysis is based on static code tracing: `add_pending_delegator_rewards` is the only writer of the field [5](#0-4) , and `calculate_block_reward` reads it every epoch without any observed corresponding decrement in the calculation/distribution pipeline [3](#0-2) [6](#0-5) . A full reproduction would require running two consecutive epochs with `block_revenue_sharing` enabled, depositing a fixed amount via `deposit_delegator_rewards`, and confirming the same balance is credited to stakers across both epochs.

### Citations

**File:** programs/vote/src/vote_state/mod.rs (L974-988)
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
}
```

**File:** programs/vote/src/vote_state/handler.rs (L190-209)
```rust
    pub(crate) fn pending_delegator_rewards(&self) -> u64 {
        match &self.target_state {
            TargetVoteState::V4(v4) => v4.pending_delegator_rewards,
        }
    }

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

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L239-298)
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
