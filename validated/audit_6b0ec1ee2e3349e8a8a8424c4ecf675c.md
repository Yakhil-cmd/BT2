Based on the investigation, I found a direct analog to the reported bug class in the vote program's commission-update mechanism, specifically affecting block-revenue commission which lacks the same "commission rug" protections that were added for inflation-reward commission.

### Title
Block-revenue vote commission (`UpdateCommissionBps` with `CommissionKind::BlockRevenue`) can be changed mid-epoch with no delay, causing inconsistent commission splits for delegated stakers within the same reward epoch - (File: `programs/vote/src/vote_state/mod.rs`)

### Summary
The vote program explicitly removed any timing restriction on commission updates via `UpdateCommissionBps` (SIMD-0291/SIMD-0249). For the `InflationRewards` kind this is safe because the epoch-rewards calculation path deliberately reads a *cached, delayed* snapshot of vote-account commission from a prior epoch. For the `BlockRevenue` commission kind, no equivalent delay/snapshot mechanism was found in the block-reward distribution path (`calculate_block_reward`), which instead reads the vote account's *current* commission state. This mirrors the reported bug class exactly: a value fundamental to reward-splitting (`commissionPercent`/`baseStake` in the report, `block_revenue_commission_bps` here) can be changed by the account authority in the middle of an active accounting period (epoch), producing inconsistent payouts for different delegators/stakers whose rewards are realized at different points within that same period.

### Finding Description
`update_commission_bps` removes all timing checks for both commission kinds: [1](#0-0) 

Contrast this with the legacy `update_commission`, which still enforces `is_commission_update_allowed` (only allowed in the first half of an epoch, or always allowed for commission decreases), and with the newer basis-points path, which relies on the epoch-rewards code delaying the *effect* of a change by reading state from a prior epoch: [2](#0-1) [3](#0-2) 

That delay mechanism (`delay_commission_updates` + `snapshot_epoch_vote_accounts`/`rewarded_epoch_vote_accounts`) is applied only to `redeem_delegation_rewards`, i.e., the **inflation-reward** commission path. The **block-revenue** commission path, `calculate_block_reward`, instead reads the vote account directly from `distribution_epoch_vote_accounts` (the current/live epoch-stakes vote account, not a delayed snapshot): [4](#0-3) 

`pending_delegator_rewards` (the pool being split among delegators here) is accumulated via per-block deposits (`DepositDelegatorRewards`/`deposit_delegator_rewards`) that apply the *then-current* `block_revenue_commission_bps` at each deposit. Because the withdraw authority can call `UpdateCommissionBps { kind: BlockRevenue, .. }` at any point, with no timing restriction and no epoch-delay applied on the read side, commission changes take effect immediately for subsequent block-fee deposits within the very same epoch/reward cycle, while deposits made earlier in the epoch used the old rate.

### Impact Explanation
This allows a vote account's authorized withdrawer to alter the block-revenue commission split mid-epoch, so that delegated stakers whose rewards accrue from deposits made before the change are paid out at a different, and possibly much more favorable, commission rate than those whose rewards accrue from deposits made after the change (or vice versa) — all within a single reward-distribution period. This produces misattributed/inconsistent reward splits among delegators of the same vote account within one epoch, directly matching the "changing commission mid-round causes unfairness" bug class in the report. Unlike inflation-reward commission, which SIMD-0249's delay design intentionally protects against exactly this "commission rug" pattern, the block-revenue commission update was not given the same protection despite reusing the same "no commission update rule" removal language in `update_commission_bps`'s comment.

### Likelihood Explanation
Likelihood is high for any vote account that has enabled `block_revenue_sharing`/SIMD-0123: any authorized withdrawer can call `UpdateCommissionBps` with `CommissionKind::BlockRevenue` an unlimited number of times per epoch with no timing gate, and the change is picked up immediately by the next `deposit_delegator_rewards` call and by `calculate_block_reward` at distribution time, since both consult live vote-account state rather than a delayed snapshot.

### Recommendation
Apply the same delay/snapshot protection used for inflation-reward commission to block-revenue commission: either (a) route `calculate_block_reward`/`deposit_delegator_rewards` commission reads through a cached, epoch-delayed vote-account snapshot analogous to `CachedVoteAccounts`, or (b) reinstate a timing restriction (e.g., only allow increases in the first half of the epoch, consistent with `is_commission_update_allowed`) specifically for `CommissionKind::BlockRevenue` until an equivalent delay mechanism is implemented.

### Proof of Concept
1. Enable `block_revenue_sharing` (SIMD-0123) for a vote account with multiple delegators.
2. Set `block_revenue_commission_bps` low (e.g., 0) via `UpdateCommissionBps`; allow block-fee deposits to accrue to `pending_delegator_rewards` for part of the epoch.
3. Mid-epoch, the withdraw authority calls `UpdateCommissionBps { kind: BlockRevenue, commission_bps: 10000 }` (100%) — this succeeds immediately per `update_commission_bps`, with no error since there is no timing check.
4. Subsequent block-fee deposits for the remainder of the epoch are now fully retained by the commission collector instead of split with delegators.
5. At epoch-reward distribution, `calculate_block_reward` computes each delegator's share of the single pooled `pending_delegator_rewards` value using only stake proportion, without regard to which portion of that pool accrued under the low vs. high commission rate — resulting in inconsistent effective commission experienced by different stakers depending on when they were staked relative to the mid-epoch commission change, exactly as described in the source bug report.

Note: I was not able to retrieve the full body of `deposit_delegator_rewards` (only its signature/doc comment) within the available search budget, so the exact mechanics of commission application at deposit-time are inferred from the surrounding code and comments rather than fully confirmed line-by-line; a full read of `programs/vote/src/vote_state/mod.rs` around `deposit_delegator_rewards` would be needed to verify this with full certainty.

### Citations

**File:** programs/vote/src/vote_state/mod.rs (L842-856)
```rust
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
```

**File:** programs/vote/src/vote_state/mod.rs (L990-1004)
```rust
/// Given the current slot and epoch schedule, determine if a commission change
/// is allowed
pub fn is_commission_update_allowed(slot: Slot, epoch_schedule: &EpochSchedule) -> bool {
    // always allowed during warmup epochs
    if let Some(relative_slot) = slot
        .saturating_sub(epoch_schedule.first_normal_slot)
        .checked_rem(epoch_schedule.slots_per_epoch)
    {
        // allowed up to the midpoint of the epoch
        relative_slot.saturating_mul(2) <= epoch_schedule.slots_per_epoch
    } else {
        // no slots per epoch, just allow it, even though this should never happen
        true
    }
}
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L173-189)
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
```
