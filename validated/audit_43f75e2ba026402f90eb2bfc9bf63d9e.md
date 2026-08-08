### Title
Block-Revenue Reward Distribution Pays Out Accumulated `pending_delegator_rewards` Based on a Single End-of-Epoch Stake Snapshot, Enabling Late-Stake Reward Capture - ([File: runtime/src/bank/partitioned_epoch_rewards/calculation.rs])

### Summary
The external report describes a sandwich attack in which a user deposits into a vault right before a "yield update" transaction increases total assets, then withdraws immediately after, capturing yield they never actually helped generate, at the expense of long-term depositors. The vault's flaw is that the price/yield update is a discrete, snapshot-based event that pays out accumulated returns pro‑rata to whoever holds a claim *at the moment of the snapshot*, without regard to how long that claim was actually held during the accrual period.

Agave's SIMD-0123 "Block Revenue Sharing" reward path (`calculate_block_reward`) has the same structural pattern applied to stake/reward accounting: `pending_delegator_rewards` accumulates in a vote account via `deposit_delegator_rewards()` [1](#0-0)  at arbitrary times/rates, but is paid out once per epoch to whichever delegators are "effective" for `rewarded_epoch`, weighted purely by their end-of-epoch effective stake — not by how long they were actually staked while that revenue was accruing.

### Finding Description
`calculate_block_reward()` computes each delegator's share of a vote account's `pending_delegator_rewards` using only two point-in-time quantities: the delegator's `delegation_effective_stake` at `rewarded_epoch`, and `total_active_stake` taken from `RewardEpochDelegatedStakes`, itself a snapshot of stake as of the epoch boundary: [2](#0-1) 

`pending_delegator_rewards` is not scoped to a single epoch's worth of activity — it is simply an accumulator that can be topped up at any block via the permissionless `DepositDelegatorRewards` vote instruction: [1](#0-0) [3](#0-2) 

Because the payout formula (`pending_delegator_rewards * stake / total_active_stake`) contains no time-weighting term and no check on how much of the accrual period the delegator was actually staked, a delegator whose stake only became "effective" at the very end of the accrual window receives the exact same proportional share as a delegator who was staked for the entire window. This is the same root cause as the reported MultipliVault issue: a value that accrues continuously (yield / block revenue) is distributed based on an instantaneous balance snapshot rather than a time-integrated one, so it is possible to acquire a large claim just before the snapshot and immediately reduce/withdraw it afterward, capturing a disproportionate share of rewards that had nothing to do with the depositor's actual contribution period.

The reward calculation code itself acknowledges the imprecision of this pro-rata split (clamping for potential over/under-counting), which reflects that the formula does not attempt any time-based apportionment: [4](#0-3) 

### Impact Explanation
If a delegator can cause their `delegation_effective_stake(..., rewarded_epoch, ...)` to be large at exactly the epoch used for the block-reward snapshot while having contributed little/no stake during most of the period over which `pending_delegator_rewards` accrued, they receive lamports properly attributable to other, longer-term delegators of that vote account. This is a reward-misattribution issue: honest long-term stakers are diluted, and lamports are paid to a party whose stake did not back the validator's block production/commission revenue for the period being compensated. This falls squarely within the "misattributed or duplicated rewards" acceptance category for epoch/stake reward-distribution paths.

### Likelihood Explanation
This is reachable by any unprivileged staker using ordinary, permissionless stake-program and vote-program instructions (delegate, deactivate, withdraw) — no validator/operator privilege is required. The main constraint is Solana's normal stake warmup/cooldown mechanics: a fresh delegation is not "effective" until the epoch after `activation_epoch`, which limits (but does not eliminate) how tightly a staker can time entry relative to a specific reward snapshot, especially in an under-subscribed cluster where warmup is effectively immediate at the epoch boundary. `pending_delegator_rewards` values and vote-account state are fully public, so the timing/observability precondition from the report (visibility of the pending balance before the "update") is trivially satisfied on-chain.

### Recommendation
Introduce a time-weighting or minimum-holding-period component to the block-revenue distribution in `calculate_block_reward()`/`calculate_reward_points_partitioned` for SIMD-0123 rewards — e.g., weight each delegator's share by the fraction of the accrual window their delegation was actually effective (analogous to how `stake_history`-based `activating`/`effective` stake already tracks partial-epoch activation), rather than by a single end-of-epoch effective-stake snapshot. Alternatively, require a delegator to have been fully effective for the entire epoch(s) over which `pending_delegator_rewards` accumulated before being eligible for a share of the current distribution, mirroring the recommendation in the original report to add deposit/withdrawal delays before eligibility for yield.

### Proof of Concept
Conceptual sequence (constrained by Solana's normal warmup rules, which is why this is not a full same-block sandwich but an analogous "just-in-time stake" attack):
1. Observe on-chain that a target vote account has accumulated a large `pending_delegator_rewards` value via repeated `DepositDelegatorRewards` calls over an epoch (publicly visible in vote account state, per `add_pending_delegator_rewards` in [5](#0-4) ).
2. Delegate a large stake to that vote account at the earliest point that guarantees full "effective" status by `rewarded_epoch` (e.g., the epoch boundary before the epoch used in the snapshot; in an under-subscribed cluster this can be as little as one epoch, with no requirement to have been staked during the period the revenue actually accrued).
3. When the bank computes rewards for `rewarded_epoch` via `calculate_block_reward`, the attacker's stake is counted at full `delegation_effective_stake`, and the formula `pending_delegator_rewards * stake / total_active_stake` in [6](#0-5)  pays them a full pro-rata share of rewards that accrued largely before their stake existed.
4. Immediately deactivate/withdraw the stake after the reward is credited, exiting with a share of revenue not attributable to their actual staking period — diluting the payout that long-term delegators of the same vote account would otherwise have received.

Note: I was unable to fully verify within the available index whether any additional epoch-count/accrual-duration guard exists elsewhere in the reward-distribution pipeline (e.g., in `distribution.rs`) that might partially mitigate this; the search of `pending_delegator_rewards` usage was limited to `calculation.rs`. If such a mitigation exists, it should be confirmed by reviewing the full reward-distribution code path.

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
