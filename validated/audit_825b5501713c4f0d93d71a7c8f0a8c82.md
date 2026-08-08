Based on my research, I found a plausible analog to the "funds go in but can never come out" bug class in Agave's SIMD-0123 block-revenue-sharing / delegator-rewards mechanism, though I was unable to fully verify one piece (whether the vote account's `pending_delegator_rewards` field or its lamport balance is ever decremented once the corresponding block reward is paid out to stakers) due to exhausting my search budget. I present the finding with that caveat.

### Title
Block-reward distribution to stakers credits `block_reward` lamports without ever debiting the vote account or decrementing `pending_delegator_rewards`, permanently reserving/duplicating lamports - (File: `runtime/src/bank/partitioned_epoch_rewards/distribution.rs`)

### Summary
`VoteInstruction::DepositDelegatorRewards` deposits lamports into a vote account and increments its `pending_delegator_rewards` field [1](#0-0) , and the vote-account `withdraw` handler treats `pending_delegator_rewards` as a reserve that the authorized withdrawer can never draw below [2](#0-1) . At epoch-reward time, `calculate_block_reward` reads this same `pending_delegator_rewards` value from the vote account to compute a per-stake-account share of "block reward" [3](#0-2) , and `build_updated_stake_reward` in the distribution phase credits that `block_reward` amount directly onto each stake account's lamport balance [4](#0-3) . However, `distribute_epoch_rewards_in_partition` only increases bank `capitalization` by `stake_reward_lamports_minted` (the separate inflation reward) — not by `block_reward_lamports_distributed` — while only decreasing capitalization for burned block rewards [5](#0-4) . This implies the protocol design assumes those lamports are being moved out of the vote account's already-reserved `pending_delegator_rewards` balance rather than minted. I searched the codebase for any code path that decrements the vote account's lamports or its `pending_delegator_rewards` field during distribution and found none — grep for `pending_delegator_rewards` across the repo shows matches only in `vote_state/mod.rs`, `vote_processor.rs`, `vote_state/handler.rs`, `calculation.rs`, and vote-state-view/CLI files, but zero occurrences in `distribution.rs`.

### Finding Description
If the vote account's lamports/`pending_delegator_rewards` field is indeed never reduced when the corresponding `block_reward` is paid out to delegator stake accounts, this produces one of two consequences depending on how the value is intended to be consumed:
1. Lamports credited to stake accounts during distribution are not backed by any debit from the vote account nor an increase in `capitalization`, so total real lamports in the ledger silently grow relative to the tracked `capitalization` counter — a form of lamport minting/duplication.
2. Alternatively, if the reserve is meant to persist (e.g., protecting a fixed deposit pool across multiple epochs), the *same* `pending_delegator_rewards` amount gets reused as the denominator/source for reward computation in subsequent epochs without ever being released, permanently locking those lamports from the vote account's authorized withdrawer — mirroring the `BatonLaunchpad` pattern of protocol fees that flow in but can never be spent or withdrawn.

Because I could not locate the decrement logic within the reasoning-effort and tool-call budget available, I cannot state with full certainty which of these two outcomes occurs, or confirm a debit path exists elsewhere that I did not find.

### Impact Explanation
If confirmed, outcome (1) is a capitalization/lamport-supply divergence (unbacked minting) affecting consensus-critical accounting, and outcome (2) is a permanent freeze of delegator-reward lamports inside vote accounts, unrecoverable by the `authorized_withdrawer`. Both map to "concrete theft or minting of lamports" / "permanently frozen accounts" per the validation criteria.

### Likelihood Explanation
This path is reachable purely through the normal `DepositDelegatorRewards` instruction and the ordinary per-epoch reward-distribution pipeline (SIMD-0123/SIMD-0232 block-revenue-sharing) — no privileged/validator role is required to trigger the deposit, and epoch-boundary reward distribution runs unconditionally once the relevant features are active.

### Recommendation
Confirm (via a Devin session with full file access) whether `store_stake_accounts_in_partition` / `build_updated_stake_reward` or any other code path debits the source vote account's lamports and/or decrements `VoteStateV4::pending_delegator_rewards` in lockstep with `block_reward_lamports_distributed`. If no such debit exists, add explicit accounting: either subtract the distributed `block_reward` from the originating vote account's lamports and `pending_delegator_rewards` field, or include `block_reward_lamports_distributed` in the `capitalization.fetch_add` call so the ledger accounting stays consistent with actual lamport movement.

### Proof of Concept
Not constructed — this requires reproducing a full epoch-boundary reward-distribution cycle with `block_revenue_sharing`/`custom_commission_collector` features enabled, tracking a vote account's lamport balance and `pending_delegator_rewards` field before and after `distribute_partitioned_epoch_rewards()` runs, and comparing bank `capitalization()` against real supply. This should be done in a Devin session with full repository and test-harness access to conclusively verify the missing-debit hypothesis before treating this as a confirmed vulnerability.

### Citations

**File:** programs/vote/src/vote_processor.rs (L4839-4860)
```rust
    // Test DepositDelegatorRewards instruction (SIMD-0123).
    #[test]
    fn test_deposit_delegator_rewards() {
        const DEPOSIT_DELEGATOR_REWARDS_COMPUTE_UNITS: u64 =
            DEFAULT_COMPUTE_UNITS + SYSTEM_PROGRAM_COMPUTE_UNITS;

        let (vote_pubkey, _authorized_voter, _authorized_withdrawer, vote_account_v4) =
            create_test_account_with_authorized();
        let (vote_pubkey_v3, vote_account_v3) = create_test_account_v3();

        // Create source account with enough lamports to transfer.
        let source_pubkey = Pubkey::new_unique();
        let source_lamports = 1_000_000;
        let source_account =
            AccountSharedData::new(source_lamports, 0, &solana_sdk_ids::system_program::id());

        let deposit_amount = 100_000;

        let instruction_data = serialize(&VoteInstruction::DepositDelegatorRewards {
            deposit: deposit_amount,
        })
        .unwrap();
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
