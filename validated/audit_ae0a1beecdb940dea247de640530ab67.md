Based on my investigation, I found a strong analog to the "rewards squatting" bug class in the block-revenue-sharing reward path.

### Title
Unbounded, undecremented `pending_delegator_rewards` balance lets late/opportunistic stakers repeatedly squat on a vote account's entire lifetime block-revenue pool - (File: `runtime/src/bank/partitioned_epoch_rewards/calculation.rs`)

### Summary
SIMD-0123's `DepositDelegatorRewards` instruction lets **anyone** permissionlessly top up a vote account's `pending_delegator_rewards` field [1](#0-0) , which accumulates via `checked_add` [2](#0-1) . Every epoch, `calculate_block_reward` distributes a *pro-rata share of that entire accumulated balance* to whichever stake happens to be delegated to the vote account at that moment, using only the current epoch's stake ratio as the split key [3](#0-2) . I could not locate any code path that decrements/consumes `pending_delegator_rewards` after it is used to compute a payout - the only mutator found in the codebase is the deposit's `add_pending_delegator_rewards`, and the field is only ever read (not reduced) inside `calculate_block_reward`.

### Finding Description
This mirrors the external report's "rewards squatting" pattern: a lump-sum reward pool (analogous to the ERC20 "future reward token") is allocated to whatever stake happens to be present at distribution time, without any mechanism to track which epoch(s) the deposit belongs to or to prevent late-joining stake from capturing a disproportionate/duplicated share of previously-deposited value.

Concretely:
1. Anyone (not just the validator) can call `DepositDelegatorRewards` to add lamports to `pending_delegator_rewards` on a target vote account [4](#0-3) .
2. During the next epoch-boundary calculation, `calculate_block_reward` computes each delegated stake's share as `pending_delegator_rewards * stake / total_active_stake`, capped at `pending_delegator_rewards` [5](#0-4) .
3. This full-balance calculation happens on every reward-calculation pass (`calculate_stake_rewards_and_commissions`, called each epoch and again on `recalculate_stake_rewards` for recalculation) [6](#0-5) [7](#0-6) , but nowhere in `vote_state/mod.rs`, `vote_state/handler.rs`, or the calculation/distribution modules is `pending_delegator_rewards` ever reduced by the amount actually paid out.
4. Because the denominator is the *current* epoch's total delegated stake and the numerator is the *entire, never-decremented* `pending_delegator_rewards`, a staker who delegates (or re-delegates) into the vote account after a deposit lands - or simply an existing delegator across multiple subsequent epochs - can receive proportional shares of the same balance repeatedly rather than the balance being drawn down as it is paid.

### Impact Explanation
If confirmed by dynamic testing, this results in **misattributed and duplicated rewards**: lamports credited as `block_reward` to stake accounts [8](#0-7)  are added to stake delegation balances and increase `capitalization` at distribution time [9](#0-8) , without a corresponding decrease in the vote account's `pending_delegator_rewards`/lamports pool. This is capital that can be effectively minted repeatedly from a single deposit across multiple epochs, or unfairly captured by unprivileged stakers who time their delegation to land right as a large deposit is visible on-chain, diluting the rewards intended for the original long-term delegators - directly matching the "misattributed or duplicated rewards" and "minting of lamports" acceptance criteria.

### Likelihood Explanation
`DepositDelegatorRewards` is fully permissionless (any signer with lamports can call it) and requires only that the vote account be V4 with `commission_rate_in_basis_points`, `custom_commission_collector`, and `block_revenue_sharing` features active [10](#0-9) . Any unprivileged staker delegated to a vote account benefits from this miscalculation every epoch it recurs, with no special privilege required - staking/delegating is a standard unprivileged-user action.

### Recommendation
Verify (via tracing the actual lamport flow at distribution/`store_stake_accounts_in_partition`) whether `pending_delegator_rewards` is intended to be decremented elsewhere (e.g., in a commission-account store step not captured by my search) - if it is genuinely never decremented, `calculate_block_reward` must subtract the total lamports paid out from `pending_delegator_rewards` in the same pass (mirroring how inflation `point_value.rewards` is consumed once per epoch), and the deposit/distribution should be snapshotted so only stake active *before* a deposit is eligible to draw from it, preventing late-arriving stake from squatting on previously accrued block-revenue rewards.

### Proof of Concept
Not independently executed; based on static analysis:
1. Vote account `V` has `pending_delegator_rewards = X` after a `DepositDelegatorRewards` call.
2. Delegate stake `S1` to `V`, wait for full activation.
3. At epoch boundary, `calculate_block_reward` pays `S1` a share of `X` based on `S1 / total_active_stake` [11](#0-10) ; `X` in the vote account state is not reduced.
4. In the following epoch (with no new deposit), the same `X` is used again as the numerator for whatever stake is then delegated - including newly-activated stake `S2` that joined after the original deposit - allowing `S2` to also draw against the original `X`, i.e., duplicate/misattributed payout from a single deposit across multiple epochs.

**Uncertainty**: I was unable to conclusively rule out a decrement mechanism located outside the files I searched (e.g., inside `store_commission_accounts_partitioned` or a related SIMD-0123 settlement step not surfaced by my searches), given the index's size limits. Confirming this requires a Devin session with full repository access to trace every write site of the `pending_delegator_rewards` field and validate the exact lamport accounting across `begin_partitioned_rewards`, `distribute_reward_commissions`, and `store_stake_accounts_in_partition`.

### Citations

**File:** programs/vote/src/vote_state/mod.rs (L935-951)
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
```

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

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L173-231)
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

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L1076-1087)
```rust
        let (_, StakeRewardCalculation { stake_rewards, .. }) = self
            .calculate_stake_rewards_and_commissions(
                &stake_history,
                stake_delegations,
                cached_vote_accounts,
                rewarded_epoch,
                point_value,
                &ag_epoch_type,
                thread_pool,
                null_tracer(),
                &mut RewardsMetrics::default(), // This is required, but not reporting anything at the moment
            );
```

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L192-194)
```rust
        // increase total capitalization by the distributed rewards
        self.capitalization
            .fetch_add(stake_reward_lamports_minted, Relaxed);
```

**File:** programs/vote/src/vote_processor.rs (L409-426)
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
        }
```
