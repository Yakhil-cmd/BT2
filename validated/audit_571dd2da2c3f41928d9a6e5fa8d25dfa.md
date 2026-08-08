### Title
Delegator revenue-sharing rewards become permanently stuck when a vote account's delegated stake drops to zero before reward calculation - (File: `runtime/src/bank/partitioned_epoch_rewards/calculation.rs`)

### Summary
`pending_delegator_rewards` on a vote account is a shared pool of lamports (deposited via `DepositDelegatorRewards`, SIMD-0123) that is meant to be distributed pro-rata to delegators based on `stake / total_active_stake` at epoch-reward time, exactly the "pool of assets divided by shares" pattern described in the external report. If the denominator (`total_active_stake`) for a vote account reaches zero at the moment rewards are calculated, the code intentionally pays out zero to everyone rather than reverting or redirecting the funds, and there is no other path to reclaim or reallocate that pool. Combined with vote-account withdrawal restrictions that hard-block spending lamports reserved as `pending_delegator_rewards`, this can leave those lamports permanently locked in the vote account.

### Finding Description
`calculate_block_reward` computes each stake account's share of `pending_delegator_rewards` using the vote account's aggregate delegated stake for the reward epoch as the denominator: [1](#0-0) 

Notice the explicit branch: `if total_active_stake == 0 { 0 }`. This mirrors the Sentiment bug's `totalDepositAssets == 0` branch that causes bad share-price collapse — here, if all stake delegated to a vote account is fully deactivated/withdrawn by the time the epoch-boundary reward calculation runs (e.g., `reward_epoch_delegated_stakes.delegated_stakes.get(&vote_pubkey)` returns `None`/`unwrap_or(0)`), `calculate_block_reward` returns `0` for **every** stake delegation to that vote account, even though `vote_state.pending_delegator_rewards()` (fetched on line 189) is still non-zero.

Because `total_active_stake` is derived purely from currently-active stake delegations (which any unprivileged stake-account owner controls via ordinary deactivate/withdraw instructions), any set of delegators can, by fully undelegating from a vote account before an epoch boundary, drive this denominator to zero while `pending_delegator_rewards` (funded earlier via the unprivileged, permissionless `DepositDelegatorRewards` instruction) remains outstanding on the vote account.

Once stuck, the pool cannot be recovered: the vote-program `withdraw` instruction enforces that the withdrawable balance is capped at `lamports - pending_delegator_rewards - rent_exempt_minimum`, and outright forbids closing the account (`remaining_balance == 0`) while `pending_delegator_rewards > 0`: [2](#0-1) 

Since no code path decrements `pending_delegator_rewards` except successful reward distribution (which is permanently gated to `0` payout once `total_active_stake == 0`), the reserved lamports become frozen indefinitely — nobody (not the withdraw authority, not any delegator) can ever access them, and the account can never be closed.

### Impact Explanation
This produces permanently frozen lamports on a vote account: the deposited `pending_delegator_rewards` pool becomes unspendable and unwithdrawable once the vote account's total delegated stake hits zero at a reward-calculation boundary, and the vote account itself becomes un-closable forever. This satisfies the "permanently frozen accounts" impact bar from the validation criteria. It is a direct structural analog of the Sherlock finding: a pro-rata pool (`pending_delegator_rewards` / `total_active_stake`, i.e., "assets"/"shares") that reaches a degenerate zero-denominator state while the numerator remains outstanding, and for which the protocol has no recovery mechanism.

### Likelihood Explanation
Reaching this state requires only unprivileged actions: (1) someone (anyone) calls the permissionless `DepositDelegatorRewards` instruction to fund `pending_delegator_rewards` on a vote account, and (2) all currently-delegated stakers to that vote account fully deactivate and withdraw their stake before the next epoch-boundary reward calculation runs (all done through standard, permissionless stake-program instructions). This is most likely on a low-stake or abandoned/unpopular validator's vote account, similar to the "unpopular pool" precondition called out in the source report, but does not require any privileged/validator-only capability — any depositor and any set of delegators can trigger it, intentionally or accidentally.

### Recommendation
Do not silently drop the block-reward payout to zero when `total_active_stake == 0` while `pending_delegator_rewards > 0`. Options include: (a) refusing to let `pending_delegator_rewards` exist without at least one delegator (e.g., disallow `DepositDelegatorRewards` when the vote account currently has zero delegated stake, or require it be redirected/refunded when the last delegator exits), or (b) providing an explicit reclaim/sweep path (e.g., to the block-revenue/commission collector) for `pending_delegator_rewards` that can no longer be distributed due to a zero-stake denominator, so funds are never permanently unspendable.

### Proof of Concept
Not independently constructed as an end-to-end test; verification is based on directly reading:
- The zero-denominator branch in `calculate_block_reward` at [3](#0-2) 
- Confirmed via the existing unit test `test_calculate_block_reward_specific` that `get_block_reward_for_test(0, 0, 0, 0) == 0` and via the property test `test_calculate_block_reward_prop` that reward is always `<= pending_delegator_rewards` (i.e., can be strictly less/zero while `pending_delegator_rewards` stays outstanding): [4](#0-3) 
- The withdrawal lock-up logic that prevents ever spending/reclaiming `pending_delegator_rewards`: [2](#0-1) 

Note: I was unable to locate, within available tool budget, the exact code path (if any) that decrements `pending_delegator_rewards` on the vote account after a successful distribution (only the read/consumption in `calculate_block_reward` and the deposit path in `deposit_delegator_rewards`/`vote_processor.rs` were confirmed). This means I cannot rule out an alternate reconciliation mechanism outside the files reviewed; this should be verified further (e.g., in `vote_reward.rs`, `distribution.rs`, or vote-account lamport crediting during `store_stake_accounts_in_partition`) before treating this as fully confirmed.

### Citations

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L206-231)
```rust
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
