## Finding

### Title
Permissionless `DepositDelegatorRewards` lets anyone permanently freeze another validator's vote account withdrawal/closure - (File: `programs/vote/src/vote_state/mod.rs`)

### Summary
The vote program's `DepositDelegatorRewards` instruction (SIMD-0123) can be invoked by anyone who merely signs as the *source* of the lamports; it does not require the vote account's authorized withdrawer to sign. The call increments the target vote account's `pending_delegator_rewards` field, which is enforced elsewhere as a reserved balance that blocks full withdrawal/closure of the vote account. This mirrors the reported bug class: an unprivileged party performing an action against a *target's* account-level accounting (analogous to `repayDebt()` letting anyone touch another borrower's debt bookkeeping) that can leave the target account's shared/global tracking counter in a state that DOSes normal operation for the legitimate owner.

### Finding Description
`deposit_delegator_rewards()` only requires the *source* account to sign the transfer; the vote account itself is not required to authorize the call: [1](#0-0) 

The deposited amount is added to `pending_delegator_rewards` on the target vote account via `add_pending_delegator_rewards`: [2](#0-1) [3](#0-2) 

`withdraw()` then treats `pending_delegator_rewards` as an inviolable reserve: if it is non-zero, the account cannot be fully closed (balance driven to zero), and even partial withdrawals are capped by `rent_exempt_minimum + pending_delegator_rewards`: [4](#0-3) 

The only mechanism that reduces `pending_delegator_rewards` is the epoch block-reward distribution path, `calculate_block_reward()`, which computes a distributable share proportional to `stake / total_active_stake` for that vote account, clamped to `pending_delegator_rewards`: [5](#0-4) 

Critically, if `total_active_stake` for the target vote account is `0` (e.g., an unstaked or lightly delegated validator, or any epoch where block-revenue-sharing distribution does not apply to that voter), `calculate_block_reward()` returns `0` and no reduction of `pending_delegator_rewards` occurs for that account at all.

### Impact Explanation
Any unprivileged actor holding a trivial amount of lamports (even 1 lamport, since `deposit: 0` is a no-op but `deposit: 1` succeeds) can call `DepositDelegatorRewards` against **any** vote account without any relationship to it or its authorized withdrawer. This sets `pending_delegator_rewards > 0` on the victim account. Per `withdraw()`'s logic, this permanently prevents the authorized withdrawer from fully closing/deinitializing that vote account, and restricts withdrawable balance to `lamports - rent_exempt_minimum - pending_delegator_rewards`, unless/until the on-chain block-reward-distribution mechanism organically pays down that exact amount — which does not happen at all for vote accounts with zero delegated/active stake. This produces a permanently frozen account state triggered entirely by an unprivileged party, directly matching the accepted "permanently frozen accounts" impact category.

### Likelihood Explanation
The attack requires only: (1) the relevant features enabled (`commission_rate_in_basis_points`, `custom_commission_collector`, `block_revenue_sharing` — i.e., SIMD-0123/0291/0232 active), (2) a v4 vote account target, and (3) a wallet with at least 1 lamport to deposit and sign as source. No special privileges, timing, or validator role are needed, making this trivially reachable by any transaction sender against any vote account on the network once these features are live.

### Recommendation
Require the vote account's authorized withdrawer (or another explicit vote-account-owner authorization) to co-sign or approve `DepositDelegatorRewards`, or provide the authorized withdrawer with an unconditional path to reduce/forfeit `pending_delegator_rewards` (e.g., an explicit "cancel/forgive pending rewards" instruction) so the reserve cannot be imposed unilaterally by third parties and cannot become permanently un-clearable when a vote account has zero delegated stake.

### Proof of Concept
1. Attacker (any keypair with ≥1 lamport, unrelated to the victim vote account) submits `VoteInstruction::DepositDelegatorRewards { deposit: 1 }` with accounts `[victim_vote_account (writable, not signer), attacker (writable, signer), system_program]`.
2. `verify_authorized_signer(&source_address, signers)` only checks that the attacker (source) signed — see [6](#0-5)  — no check on the vote account's withdraw authority.
3. Instruction succeeds; `victim_vote_account.pending_delegator_rewards` becomes `1`.
4. If the victim vote account currently has zero (or near-zero) active delegated stake, `calculate_block_reward()` returns `0` every epoch (see cited lines 206-213 in `calculation.rs`), so `pending_delegator_rewards` is never reduced.
5. The legitimate authorized withdrawer subsequently calls `Withdraw` for the full balance; `withdraw()` rejects it with `InstructionError::InsufficientFunds` because `pending_delegator_rewards > 0` (see cited lines 1087-1092 in `vote_state/mod.rs`), permanently blocking closure of the account.

### Citations

**File:** programs/vote/src/vote_state/mod.rs (L936-951)
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
```

**File:** programs/vote/src/vote_state/mod.rs (L980-988)
```rust
    // Update `pending_delegator_rewards`.
    let transaction_context = &invoke_context.transaction_context;
    let instruction_context = transaction_context.get_current_instruction_context()?;
    let mut vote_account =
        instruction_context.try_borrow_instruction_account(vote_account_index)?;

    vote_state.add_pending_delegator_rewards(deposit)?;
    vote_state.set_vote_account_state(&mut vote_account)
}
```

**File:** programs/vote/src/vote_state/mod.rs (L1079-1122)
```rust
    let remaining_balance = vote_account
        .get_lamports()
        .checked_sub(lamports)
        .ok_or(InstructionError::InsufficientFunds)?;

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
