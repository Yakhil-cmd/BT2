### Title
Instant `block_revenue_commission_bps` update before `DepositDelegatorRewards` allows a validator to seize delegator block-revenue rewards - (File: `programs/vote/src/vote_state/mod.rs`)

### Summary
`update_commission_bps` (SIMD-0291), which sets both `inflation_rewards_commission_bps` and `block_revenue_commission_bps` on a `VoteStateV4` account, explicitly has **no timing restriction**, unlike the legacy `update_commission` path which enforces `is_commission_update_allowed` (first-half-of-epoch rule) and unlike the inflation-rewards commission which is additionally protected at reward-calculation time by an epoch-delayed snapshot. Because `block_revenue_commission_bps` is read live (not through the delayed snapshot mechanism) whenever `DepositDelegatorRewards` is processed, a validator's authorized withdrawer can spike the commission to (near) 100% immediately before a block-revenue deposit and then lower it back, capturing delegator rewards that should have been shared — the exact bug-class described in the Audius `deployerCut` report.

### Finding Description
For the legacy/inflation path, agave explicitly defends against "last-minute commission rug" attacks in two layers:
1. `update_commission` rejects commission **increases** outside the first half of an epoch via `is_commission_update_allowed`: [1](#0-0) 
2. Even when a change is allowed, `redeem_delegation_rewards` deliberately reads the commission from an **epoch-delayed snapshot** (`snapshot_epoch_vote_accounts` / `rewarded_epoch_vote_accounts`) rather than the live vote state, specifically "to attempt to delay the effect of commission updates by at least one full epoch": [2](#0-1) 

However, `update_commission_bps` (which also controls `block_revenue_commission_bps`, used for SIMD-0123 block-revenue sharing) has no such protection at all — the code comment says so directly: [3](#0-2) 

This lack of a timing rule is confirmed by the accompanying test, which states plainly that SIMD-0291 has no timing restrictions and updates are "always allowed regardless of epoch position", including nonsensical values above 100%: [4](#0-3) [5](#0-4) 

Critically, `block_revenue_commission_bps` is *not* consumed through the epoch-reward-calculation pipeline that has the delay-snapshot protection. `calculate_block_reward` only computes each stake account's proportional share of `pending_delegator_rewards` — it contains no commission split logic at all: [6](#0-5) 

Instead, the commission split against block revenue happens at the point the validator calls `DepositDelegatorRewards`, which is processed on-demand (per instruction, not per epoch) via `vote_state::deposit_delegator_rewards`, reading whatever `block_revenue_commission_bps` is currently stored in the account at that moment: [7](#0-6) 

Because `UpdateCommissionBps { kind: CommissionKind::BlockRevenue }` has no epoch-position or delay restriction, and `DepositDelegatorRewards` uses the live value with no snapshot delay, a validator can:
1. Call `UpdateCommissionBps` to set `block_revenue_commission_bps` to 10000 (100%) or higher (values above 10000 bps are explicitly allowed at the program level per the test above) immediately before a deposit.
2. Call `DepositDelegatorRewards`, capturing the entire block-revenue deposit that should have been split with delegators.
3. Call `UpdateCommissionBps` again to restore a normal commission rate, so subsequent (or previous) reward records/UI look ordinary.

This mirrors the Audius report precisely: a value that determines the delegator/service-provider split can be modified with no delay directly before a reward-distributing action is executed, letting the operator front-run reward payouts to its own delegators.

### Impact Explanation
This allows a validator operator to unilaterally and repeatedly divert block-revenue rewards that are contractually owed to delegators back to themselves, corrupting the intended reward/commission accounting for the block-revenue-sharing feature (SIMD-0123/SIMD-0291/SIMD-0232). This is a form of stake/reward corruption reachable by a single account holder (the vote account's authorized withdrawer) issuing ordinary signed transactions — no leader, network, or consensus-level privilege is required.

### Likelihood Explanation
High, once SIMD-0123 (`block_revenue_sharing`), SIMD-0291 (`commission_rate_in_basis_points`), SIMD-0232 (`custom_commission_collector`), and SIMD-0185 (VoteStateV4) are all activated (which is required for `DepositDelegatorRewards` to be usable at all). The attack requires only two ordinary vote-program instructions signed by the account's own authorized withdrawer, with no special timing window needed to align with epoch boundaries (unlike the legacy commission path). This makes it trivially and repeatedly exploitable by any validator who wants to shortchange its delegators for block-revenue rewards.

### Recommendation
Apply an equivalent protection to `block_revenue_commission_bps` (and ideally `inflation_rewards_commission_bps` set via `UpdateCommissionBps`) as exists for the legacy commission path:
- Reintroduce a timing restriction (e.g., disallow increases in the back half of an epoch, or require a minimum on-chain delay) for `UpdateCommissionBps`, at least for `CommissionKind::BlockRevenue`.
- Alternatively/additionally, have `deposit_delegator_rewards` consume a commission rate that was snapshotted prior to the deposit-triggering event (analogous to `snapshot_epoch_vote_accounts` used for inflation rewards), rather than reading the live value at deposit time.

### Proof of Concept
Not independently executed; this is derived from static code analysis (the explicit "no timing restriction" comment/test for `update_commission_bps` combined with `deposit_delegator_rewards` reading the live commission at deposit time). I was not able to fully inspect the body of `vote_state::deposit_delegator_rewards` (the exact split/transfer logic) before running out of tool budget, so the precise mechanics of how `block_revenue_commission_bps` is applied at deposit time (e.g., exact lamport split formula, whether it's clamped) remain unverified and should be confirmed by reading `programs/vote/src/vote_state/mod.rs`'s `deposit_delegator_rewards` function and its call sites in full before treating this as conclusively exploitable.

### Citations

**File:** programs/vote/src/vote_state/mod.rs (L807-815)
```rust
    let enforce_commission_update_rule = !disable_commission_update_rule
        && match vote_state_result.as_ref() {
            Ok(decoded_vote_state) => commission > decoded_vote_state.commission(),
            Err(_) => true,
        };

    if enforce_commission_update_rule && !is_commission_update_allowed(clock.slot, epoch_schedule) {
        return Err(VoteError::CommissionUpdateTooLate.into());
    }
```

**File:** programs/vote/src/vote_state/mod.rs (L827-847)
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
```

**File:** programs/vote/src/vote_state/mod.rs (L1806-1811)
```rust
    /// Test update_commission_bps (SIMD-0291).
    ///
    /// Unlike test_update_commission, SIMD-0291 has no timing restrictions
    /// (per SIMD-0249). Updates are always allowed regardless of epoch position.
    ///
    /// This test only uses V4 since SIMD-0291 depends on SIMD-0185 (VoteStateV4).
```

**File:** programs/vote/src/vote_state/mod.rs (L1924-1934)
```rust
        // There's no timing check for SIMD-0291, so just go back and forth
        // with new values.

        commission_bps_roundtrip(1_100); // Increase to 11%
        commission_bps_roundtrip(5_000); // Increase to 50%
        commission_bps_roundtrip(4_400); // Decrease to 44%
        commission_bps_roundtrip(4_600); // Increase to 46%

        // Values > 10,000 bps are allowed at program level.
        commission_bps_roundtrip(15_000); // 150%
        commission_bps_roundtrip(50_000); // 500%
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
