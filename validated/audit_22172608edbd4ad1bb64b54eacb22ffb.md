### Title
Instant, undelayed `block_revenue_commission_bps` updates allow validators to arbitrage stake-reward distribution, unlike the delayed `inflation_rewards_commission_bps` path - (File: runtime/src/bank/partitioned_epoch_rewards/calculation.rs, programs/vote/src/vote_state/mod.rs)

### Summary
The reward-distribution code deliberately delays the vote-account commission used for inflation rewards by up to a full epoch specifically "to prevent last minute commission rugs." However, `block_revenue_commission_bps` (SIMD-0291) is exempt from both the instruction-level update-timing rule and the reward-calculation delay mechanism, and is read from the *live, undelayed* vote-account snapshot when block rewards are computed. This asymmetry mirrors the "stale vs. live value" arbitrage pattern described in the Chainlink report: an entity that controls the input used in a payout calculation can change that input at will, right around the payout event, to capture value at the expense of the (unprivileged) stake delegators sharing in that reward.

### Finding Description
For inflation rewards, `redeem_delegation_rewards` intentionally uses a delayed commission value when `delay_commission_updates` is active, pulling the commission from `snapshot_epoch_vote_accounts` (state from a full epoch before) rather than the live `vote_state`: [1](#0-0) 

The `CachedVoteAccounts` struct documents this explicitly: the `snapshot_epoch_vote_accounts` field exists "to prevent last minute commission rugs," while `distribution_epoch_vote_accounts` holds the *live* end-of-epoch state: [2](#0-1) 

Block rewards, however, are computed with the undelayed, live vote-account snapshot (`cached_vote_accounts.distribution_epoch_vote_accounts`), bypassing the delay mechanism entirely: [3](#0-2) 

At the instruction level, `update_commission_bps` (which sets `block_revenue_commission_bps`) explicitly has no timing restriction, unlike the legacy `update_commission` path which enforces `is_commission_update_allowed` (only allowing increases in the first half of an epoch): [4](#0-3) [5](#0-4) 

The vote processor comment confirms this is intentional per SIMD-0291/SIMD-0123: `UpdateCommission` (legacy, percentage-based) is delay-gated by `delay_commission_updates`, while the newer basis-points commission-setting path has no equivalent gate: [6](#0-5) 

The net effect: a vote-account withdraw authority can set `block_revenue_commission_bps` to a favorable (low) value to attract delegated stake, then raise it immediately before/at the point block-reward distribution reads `distribution_epoch_vote_accounts`, extracting a larger commission share of block/priority-fee rewards for that epoch than delegators were led to expect — with no epoch-long lag protecting stakers, unlike the protection that exists for `inflation_rewards_commission_bps`.

### Impact Explanation
This directly misattributes rewards between the vote/commission-collector account and the unprivileged stake delegators sharing the block-revenue pool for that epoch: delegators receive less of the block reward pool than the commission rate they observed when delegating would suggest, because the commission used for calculation is whatever value is live at the moment of `calculate_stake_rewards_and_commissions`/`calculate_block_reward`, not a rate delegators had epoch-long visibility into. This is a reward-distribution accounting bug (misattributed rewards) reachable purely through normal, permissionless vote-account instructions and the routine end-of-epoch reward-distribution code path.

### Likelihood Explanation
Likelihood is high: `update_commission_bps` is a standard, unrestricted vote-program instruction (no timing check, unlike the legacy commission field), and any vote account owner can invoke it at any slot, including immediately before the block-reward calculation runs at epoch boundaries. No special privilege beyond normal vote-account authority is required, and the reward-calculation code path (`calculate_stake_rewards_and_commissions` → `calculate_block_reward`) runs automatically every epoch for every validator with `block_revenue_sharing` enabled.

### Recommendation
Route `block_revenue_commission_bps` through the same delayed-commission mechanism used for `inflation_rewards_commission_bps` (i.e., resolve it via `snapshot_epoch_vote_accounts`/`rewarded_epoch_vote_accounts` when `delay_commission_updates`-equivalent protection is desired) rather than reading it live from `distribution_epoch_vote_accounts`, so that delegators have a full epoch of advance notice of the effective block-revenue commission rate, consistent with the "prevent last minute commission rugs" rationale already applied to inflation rewards.

### Proof of Concept
Conceptual sequence (block_revenue_sharing enabled):
1. Vote account V advertises a low `block_revenue_commission_bps` (e.g., 0) to attract delegated stake throughout most of an epoch.
2. Near the end of the rewarded epoch (or right up to the point the bank computes `calculate_stake_rewards_and_commissions` for the distribution epoch), the vote account owner calls `UpdateCommissionBps` with a much higher value — permitted unconditionally since `update_commission_bps` has "No commission update rule" per SIMD-0291 [7](#0-6) .
3. `calculate_block_reward` is invoked with `cached_vote_accounts.distribution_epoch_vote_accounts`, which reflects this just-updated, high commission rate [3](#0-2) .
4. Delegators' stake rewards for that epoch are computed and distributed using the higher, last-minute commission rate they never had a chance to react to (e.g., by undelegating), while the inflation-rewards commission for the same vote account remains protected by the one-epoch delay.

I was not able to inspect the full body of `calculate_block_reward` (only its call site) to verify whether an additional internal delay mechanism exists there; this should be confirmed against the function's full implementation before treating this as conclusively unmitigated.

### Citations

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

**File:** programs/vote/src/vote_state/mod.rs (L797-815)
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
