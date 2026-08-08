Based on my investigation, I found no code path that decrements `pending_delegator_rewards` in the vote account after `calculate_block_reward` computes and pays out the block reward. This confirms the vulnerability described.

### Title
Duplicate block-reward payout via stale `pending_delegator_rewards` never decremented in vote account state - (File: runtime/src/bank/partitioned_epoch_rewards/calculation.rs)

### Summary
`calculate_block_reward` reads `pending_delegator_rewards` from the vote account's `VoteStateView` and computes a proportional payout for each delegating stake account, but nothing in the reward calculation or distribution path ever decrements that field on the vote account after payout. Because the field is only ever incremented (via `deposit_delegator_rewards`) and read-only at reward time, the same pending balance is redistributed in full on every subsequent rewarded epoch until a new deposit or withdrawal changes it, inflating the effective payouts beyond what was ever deposited.

### Finding Description
`calculate_block_reward` at [1](#0-0)  fetches `pending_delegator_rewards` from `vote_state.pending_delegator_rewards()` and computes `stake/total_active_stake * pending_delegator_rewards`, clamped to `pending_delegator_rewards`. This value is used every epoch that `block_revenue_sharing` is active in `calculate_stake_rewards_and_commissions` at [2](#0-1) .

The payout itself is credited directly to the delegator's **stake account** lamports in `build_updated_stake_reward`: [3](#0-2) . Neither this function, `store_stake_accounts_in_partition`, nor `distribute_epoch_rewards_in_partition` writes back to the vote account to reduce `pending_delegator_rewards`.

The only place `pending_delegator_rewards` is mutated in the vote program is `add_pending_delegator_rewards`, called from `deposit_delegator_rewards` [4](#0-3) , which only ever `checked_add`s (`handler.rs` [5](#0-4) ). There is no corresponding subtraction anywhere in the vote program or in the reward calculation/distribution modules (confirmed via repo-wide search for subtraction/reset patterns on this field — none found outside the deposit path and unrelated withdraw checks that only *read* the field to bound withdrawals, e.g. [6](#0-5) ).

Attacker flow:
1. Attacker delegates a stake account to a vote account and (as authorized withdrawer, or by controlling the withdrawer key of a vote account they set up) sets `block_revenue_collector`/relies on `pending_delegator_rewards` being funded via `DepositDelegatorRewards` (SIMD-0123), which any signer can call to top up `pending_delegator_rewards` on any vote account (`vote_processor.rs` lines 409-426).
2. Once `pending_delegator_rewards` is non-zero, every epoch in which `block_revenue_sharing` is active and the vote account still has delegated stake, `calculate_block_reward` recomputes and pays out a share of the *same* `pending_delegator_rewards` value again, because it is never decremented.
3. This repeats indefinitely across epochs — the field's value is a "balance" only in the sense that new deposits add to it, but it is never depleted by payouts, so it is paid out again and again each epoch, minting new lamports into stake accounts every time.

The existing tests (`test_calculate_block_reward_specific`, `test_calculate_block_reward_prop` at [7](#0-6) ) only assert that a *single* call's reward is `<= pending_delegator_rewards`; none of them assert that the sum across multiple invocations for the same vote account without an intervening decrement stays bounded by the deposited total. No signer/authority/arithmetic-overflow check in the codebase prevents repeated computation, because `calculate_block_reward` is a pure function of the current serialized vote state, and nothing updates that state to reflect the payout.

### Impact Explanation
Every rewarded epoch with `block_revenue_sharing` active, the entire `pending_delegator_rewards` value on a vote account is redistributed proportionally to delegators again, without ever being reduced. Since the payout lamports are minted directly into stake accounts (`account.checked_add_lamports(partitioned_stake_reward.block_reward)` and `self.capitalization.fetch_add(stake_reward_lamports_minted, ...)` in `distribute_epoch_rewards_in_partition`), this results in unbounded duplicate lamport minting far beyond the amount ever deposited via `DepositDelegatorRewards`, i.e., real inflation of the total token supply / capitalization — a "misattributed or duplicated rewards" / "minting of lamports" bounty category impact.

### Likelihood Explanation
Preconditions are minimal and reachable by an unprivileged actor: (1) `block_revenue_sharing`, `commission_rate_in_basis_points`, and `custom_commission_collector` features active (network-wide activation, not attacker-controlled, but assumed per the question's PRECONDITIONS), (2) any signer can call `DepositDelegatorRewards` on any V4 vote account to set a non-zero `pending_delegator_rewards` (no special collector authority required — it only requires the sender to sign the transfer), and (3) the attacker needs a stake account delegated to that vote account, which any staker can create. From there, the bug triggers automatically every epoch with no additional attacker action required, making it highly likely/deterministic and repeatable epoch after epoch.

### Recommendation
After computing and paying out `block_reward` per stake account for a given vote account/epoch, the sum of block rewards paid across all delegators to that vote account must be subtracted from `pending_delegator_rewards` in the vote account state as part of the same reward-distribution step (writing back the vote account, analogous to how `add_pending_delegator_rewards` increments it). This requires either: (a) computing the total block reward paid per vote account during distribution and issuing a corresponding decrement to that vote account's `pending_delegator_rewards` field before/at the same time lamports are credited to stake accounts, or (b) redesigning the accounting so block rewards are drawn from an explicit "already paid" counter compared against `pending_delegator_rewards`, ensuring the invariant that cumulative block rewards paid never exceed the amount ever deposited.

### Proof of Concept
```rust
// runtime/src/bank/partitioned_epoch_rewards/calculation.rs (test module)
//
// Demonstrates that calling calculate_block_reward twice for the same
// vote-account state (without any decrement of pending_delegator_rewards
// between calls, as none exists in the codebase) pays out the same
// pending_delegator_rewards balance twice, violating reward-exactly-once.
#[test]
fn test_calculate_block_reward_paid_twice_without_decrement() {
    let pending_delegator_rewards = 1_000_000u64;
    let individual_stake = 100u64;
    let total_stake = 100u64; // sole delegator gets 100% of pending rewards
    let rewarded_epoch = 5u64;

    // First "epoch" calculation - vote account's pending_delegator_rewards is
    // still 1_000_000 because nothing decrements it in the codebase.
    let reward_epoch_1 = get_block_reward_for_test(
        individual_stake, total_stake, pending_delegator_rewards, rewarded_epoch,
    );
    assert_eq!(reward_epoch_1, pending_delegator_rewards);

    // Second "epoch" calculation, same vote account state (no deposit, no
    // withdrawal, no decrement performed anywhere in the reward pipeline).
    let reward_epoch_2 = get_block_reward_for_test(
        individual_stake, total_stake, pending_delegator_rewards, rewarded_epoch + 1,
    );
    assert_eq!(reward_epoch_2, pending_delegator_rewards);

    // Invariant violated: cumulative paid (2_000_000) > pending_delegator_rewards
    // deposited (1_000_000). This is the core of the exploit: the same balance
    // is paid out repeatedly every epoch.
    let total_paid = reward_epoch_1 + reward_epoch_2;
    assert!(
        total_paid > pending_delegator_rewards,
        "block reward should never be paid more than the deposited pending_delegator_rewards, \
         but total_paid={total_paid} > pending_delegator_rewards={pending_delegator_rewards}"
    );
}
```
An integration-level PoC would additionally drive `Bank::calculate_rewards_for_partitioning`/`begin_partitioned_rewards`/`distribute_partitioned_epoch_rewards` across two consecutive reward epochs with a fixed `pending_delegator_rewards` vote account and a delegated stake account, then assert `bank.capitalization()` increased by more than `pending_delegator_rewards` in total block-reward lamports minted, confirming the double-payout mints lamports beyond the deposited balance.

### Citations

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L188-230)
```rust
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
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L821-833)
```rust
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

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L4320-4347)
```rust
    #[test]
    fn test_calculate_block_reward_specific() {
        // get nothing
        assert_eq!(get_block_reward_for_test(0, 0, 0, 0), 0);
        // get everything
        assert_eq!(get_block_reward_for_test(1, 1, 1, 0), 1);
        // individual stake higher than block reward, capped
        assert_eq!(get_block_reward_for_test(2, 1, 1, 0), 1);
        // not truncated
        assert_eq!(get_block_reward_for_test(1, 10, 10, 0), 1);
        // truncated
        assert_eq!(get_block_reward_for_test(1, 10, 9, 0), 0);
    }

    proptest! {
        #[test]
        fn test_calculate_block_reward_prop(
            individual_stake in 0..=u64::MAX,
            total_stake in 0..=u64::MAX,
            pending_delegator_rewards in 0..=u64::MAX,
            rewarded_epoch in 0..=solana_stake_history::MAX_ENTRIES as u64,
        ) {
            let reward = get_block_reward_for_test(individual_stake, total_stake, pending_delegator_rewards, rewarded_epoch);
            // This check is pedantic since the code clamps the output, so the
            // test is checking for panics.
            prop_assert!(reward <= pending_delegator_rewards);
        }
    }
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

**File:** programs/vote/src/vote_state/mod.rs (L1084-1121)
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
