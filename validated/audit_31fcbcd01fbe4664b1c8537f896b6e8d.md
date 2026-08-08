### Title
Vote account `UpdateCommissionBps` (block-revenue kind) has no update-timing restriction and is not delayed in the reward-calculation snapshot, letting the withdraw authority front-run the block-revenue commission to 100% and steal delegated stakers' block-revenue rewards - (File: `programs/vote/src/vote_processor.rs`, `programs/vote/src/vote_state/mod.rs`, `runtime/src/bank/partitioned_epoch_rewards/calculation.rs`)

### Summary
The legacy `UpdateCommission` vote instruction is protected against last-minute "commission rugs" two ways: an in-epoch timing rule (`is_commission_update_allowed`) and, once `delay_commission_updates` is active, a one-to-two-epoch-delayed snapshot of vote-account state used specifically for inflation-reward commission lookups. The newer `UpdateCommissionBps` instruction (SIMD-0291/SIMD-0249), however, explicitly removes the timing rule ("No commission update rule, per SIMD-0249 and SIMD-0291") for both `InflationRewards` and `BlockRevenue` commission kinds, and the block-revenue-reward calculation path does not use the delayed snapshot at all — it reads commission directly from the live, current-epoch vote-account state at reward-calculation time. This asymmetry means the withdraw authority of a vote account can raise `block_revenue_commission_bps` to the maximum (10,000 bps / 100%) immediately before block-revenue rewards are computed, diverting the entire delegator share of block-revenue rewards to itself.

### Finding Description
`update_commission_bps` in `programs/vote/src/vote_state/mod.rs` requires only the authorized withdrawer's signature and applies the new commission (up to 10,000 bps, clamped) immediately with no epoch-boundary gate: [1](#0-0) 

The instruction handler in `vote_processor.rs` documents that this bypasses the delay rule enforced for the legacy path: [2](#0-1) 

Contrast this with the legacy `UpdateCommission` handler, which explicitly disables the in-epoch timing rule only when the `delay_commission_updates` feature is active, because in that case protection is instead provided at reward-calculation time via a delayed snapshot: [3](#0-2) [4](#0-3) 

The delayed-snapshot mechanism (`CachedVoteAccounts`) is documented as existing specifically "to prevent last minute commission rugs": [5](#0-4) 

In `redeem_delegation_rewards`, the inflation-reward commission is deliberately looked up from `snapshot_epoch_vote_accounts` / `rewarded_epoch_vote_accounts` (older, cached state) when `delay_commission_updates` is enabled: [6](#0-5) 

However, the block-revenue reward path (`calculate_block_reward`) is invoked with `cached_vote_accounts.distribution_epoch_vote_accounts` — the current, undelayed vote-account snapshot for the epoch being distributed — rather than the delayed snapshot used for inflation rewards: [7](#0-6) 

Because `UpdateCommissionBps` has no timing gate and the block-revenue commission read at distribution time is not delayed, a vote account's withdraw authority can submit `UpdateCommissionBps { commission_bps: 10_000, kind: BlockRevenue }` at any point right up to when block-revenue rewards for that epoch are calculated, capturing 100% of the block-revenue reward that should be split with delegated stakers — directly mirroring the reported pattern of a pool "manager" front-running a fee parameter to its maximum right before value is distributed to depositors.

### Impact Explanation
This allows a vote account's withdraw authority (an operator role) to unilaterally and instantly redirect block-revenue rewards away from unprivileged delegated stakers to itself, at the moment of reward calculation, with no delay or timelock to let stakers react (e.g., by undelegating). This is a concrete misattribution/theft of lamports from the stake-reward distribution path, matching the "misattributed or duplicated rewards" and "concrete theft ... of lamports" acceptance criteria. The severity is bounded by the fact that only the block-revenue commission share (not the full stake principal) is at risk, and by the same "vaults not finalized" style practical mitigation cited in the original report (informed stakers can choose not to delegate to a vote account with a suspicious commission history), similar to the original medium-severity judgment.

### Likelihood Explanation
Likelihood is limited by two factors: (1) `commission_rate_in_basis_points`, `delay_commission_updates`, `block_revenue_sharing`, and `custom_commission_collector`/Vote State V4 must all be active features, so this only applies to a specific feature configuration; and (2) stakers must have delegated stake and be relying on the honesty of the vote account operator's commission, which is a normal expectation for any commission-based reward split. Given that `UpdateCommissionBps` is a permissionless self-service instruction requiring only the account's own withdraw-authority signature, and no on-chain rule prevents rapid toggling right before reward calculation, exploitation requires no special access beyond controlling one's own vote account.

### Recommendation
Apply the same delay/timelock protection used for inflation-reward commission (`delay_commission_updates`'s snapshot-based lookup via `snapshot_epoch_vote_accounts`/`rewarded_epoch_vote_accounts`) to the block-revenue commission path in `calculate_block_reward`, instead of reading commission from the live `distribution_epoch_vote_accounts`. Alternatively, reintroduce an explicit in-epoch timing restriction for `UpdateCommissionBps` (mirroring `is_commission_update_allowed`) so that any commission increase submitted late in an epoch does not take effect until the reward for that epoch has already been calculated against the prior value.

### Proof of Concept
1. Vote account operator delegates stake normally; `block_revenue_commission_bps` starts low (e.g., 0–500 bps), attracting stakers.
2. Near the end of an epoch, immediately before/at the point the bank computes block-revenue rewards for that epoch (`calculate_stake_rewards_and_commissions` → `calculate_block_reward`, using `distribution_epoch_vote_accounts`), the withdraw authority sends `VoteInstruction::UpdateCommissionBps { commission_bps: 10_000, kind: CommissionKind::BlockRevenue }`.
3. Because `update_commission_bps` has "No commission update rule" (`programs/vote/src/vote_state/mod.rs:844`) the change is applied instantly and is visible in `distribution_epoch_vote_accounts` used by `calculate_block_reward` at `runtime/src/bank/partitioned_epoch_rewards/calculation.rs:815-834`.
4. Block-revenue rewards for that epoch are then split with 100% going to the vote account (voter) and 0% to delegated stakers, whereas under the legacy inflation-commission path the equivalent last-minute change would have been ignored in favor of the epoch-delayed snapshot value.

### Citations

**File:** programs/vote/src/vote_state/mod.rs (L797-825)
```rust
pub fn update_commission<S: std::hash::BuildHasher>(
    vote_account: &mut BorrowedInstructionAccount,
    target_version: VoteStateTargetVersion,
    commission: u8,
    signers: &HashSet<Pubkey, S>,
    epoch_schedule: &EpochSchedule,
    clock: &Clock,
    disable_commission_update_rule: bool,
) -> Result<(), InstructionError> {
    let vote_state_result = get_vote_state_handler_checked(vote_account, target_version);
    let enforce_commission_update_rule = !disable_commission_update_rule
        && match vote_state_result.as_ref() {
            Ok(decoded_vote_state) => commission > decoded_vote_state.commission(),
            Err(_) => true,
        };

    if enforce_commission_update_rule && !is_commission_update_allowed(clock.slot, epoch_schedule) {
        return Err(VoteError::CommissionUpdateTooLate.into());
    }

    let mut vote_state = vote_state_result?;

    // current authorized withdrawer must say "yay"
    verify_authorized_signer(vote_state.authorized_withdrawer(), signers)?;

    vote_state.set_commission(commission);

    vote_state.set_vote_account_state(vote_account)
}
```

**File:** programs/vote/src/vote_state/mod.rs (L827-859)
```rust
/// Update the vote account's commission in basis points (SIMD-0291, SIMD-0123).
pub fn update_commission_bps<S: std::hash::BuildHasher>(
    vote_account: &mut BorrowedInstructionAccount,
    target_version: VoteStateTargetVersion,
    commission_bps: u16,
    kind: CommissionKind,
    signers: &HashSet<Pubkey, S>,
    block_revenue_sharing_enabled: bool,
) -> Result<(), InstructionError> {
    // Per SIMD-0291: BlockRevenue returns InvalidInstructionData unless
    // SIMD-0123 (block_revenue_sharing) is enabled.
    if matches!(kind, CommissionKind::BlockRevenue) && !block_revenue_sharing_enabled {
        return Err(InstructionError::InvalidInstructionData);
    }

    let mut vote_state = get_vote_state_handler_checked(vote_account, target_version)?;

    // No commission update rule, per SIMD-0249 and SIMD-0291.

    // Require authorized withdrawer to sign.
    verify_authorized_signer(vote_state.authorized_withdrawer(), signers)?;

    match kind {
        CommissionKind::InflationRewards => {
            vote_state.set_inflation_rewards_commission_bps(commission_bps);
        }
        CommissionKind::BlockRevenue => {
            vote_state.set_block_revenue_commission_bps(commission_bps);
        }
    }

    vote_state.set_vote_account_state(vote_account)
}
```

**File:** programs/vote/src/vote_processor.rs (L202-220)
```rust
        VoteInstruction::UpdateCommission(commission) => {
            let sysvar_cache = invoke_context.environment_config.sysvar_cache();

            // Disable the commission update rule after the "delay commission
            // update" feature is activated because it imposes a minimum delay
            // of one full epoch before the new commission rate takes effect.
            let disable_commission_update_rule =
                invoke_context.get_feature_set().delay_commission_updates;

            vote_state::update_commission(
                &mut me,
                target_version,
                commission,
                &signers,
                sysvar_cache.get_epoch_schedule()?.as_ref(),
                sysvar_cache.get_clock()?.as_ref(),
                disable_commission_update_rule,
            )
        }
```

**File:** programs/vote/src/vote_processor.rs (L362-382)
```rust
        VoteInstruction::UpdateCommissionBps {
            commission_bps,
            kind,
        } => {
            // SIMD-0291: Commission Rate in Basis Points
            // Requires SIMD-0185: Vote State V4
            // Requires SIMD-0249: Delay Commission Updates
            let feature_set = invoke_context.get_feature_set();
            if !feature_set.commission_rate_in_basis_points || !feature_set.delay_commission_updates
            {
                return Err(InstructionError::InvalidInstructionData);
            }
            vote_state::update_commission_bps(
                &mut me,
                target_version,
                commission_bps,
                kind,
                &signers,
                feature_set.block_revenue_sharing,
            )
        }
```

**File:** runtime/src/bank/partitioned_epoch_rewards/mod.rs (L305-319)
```rust
pub(super) struct CachedVoteAccounts<'a> {
    /// Snapshot of vote account state from the beginning of the epoch prior to
    /// the rewarded epoch. This snapshot state is saved a full epoch before
    /// being used to prevent last minute commission rugs.
    ///
    /// Developer note: This field is `Option` to handle large bank warps
    pub(super) snapshot_epoch_vote_accounts: Option<&'a VoteAccounts>,
    /// Vote account state from the beginning of the rewarded epoch.
    ///
    /// Developer note: This field is `Option` to handle large bank warps
    pub(super) rewarded_epoch_vote_accounts: Option<&'a VoteAccounts>,
    /// Vote account state from the end of the rewarded epoch / beginning of the
    /// distribution epoch.
    pub(super) distribution_epoch_vote_accounts: &'a VoteAccounts,
}
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L703-724)
```rust
        // Fetch the voter commission from past epochs to attempt to
        // delay the effect of commission updates by at least one
        // full epoch.
        // When `commission_rate_in_basis_points` is true, use the new field
        // `inflation_rewards_commission_bps`; otherwise use the legacy
        // percentage field and convert to basis points by multiplying by 100.
        let commission_bps = if delay_commission_updates {
            let vote_state_for_commission = snapshot_epoch_vote_accounts
                .and_then(|eva| eva.get(&vote_pubkey))
                .or_else(|| rewarded_epoch_vote_accounts.and_then(|eva| eva.get(&vote_pubkey)))
                .map(|vote_account| vote_account.vote_state_view())
                .unwrap_or(vote_state);
            if commission_rate_in_basis_points {
                vote_state_for_commission.inflation_rewards_commission()
            } else {
                vote_state_for_commission.commission() as u16 * 100
            }
        } else if commission_rate_in_basis_points {
            vote_state.inflation_rewards_commission()
        } else {
            vote_state.commission() as u16 * 100
        };
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L815-834)
```rust
        let rewards_accumulator: RewardsAccumulator = thread_pool.install(|| {
            stake_delegations
                .par_iter()
                .zip(&mut stake_rewards.spare_capacity_mut()[..stake_delegations_len])
                .with_min_len(500)
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
                    let maybe_reward_record = self.redeem_delegation_rewards(
```
