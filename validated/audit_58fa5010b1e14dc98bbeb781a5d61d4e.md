### Title
Vote commission (SIMD-0291) can be updated to values above 100% with no timelock, unlike the legacy commission-update path - (File: `programs/vote/src/vote_state/mod.rs`)

### Summary
`update_commission_bps` (the SIMD-0291 basis-points commission update, reachable via the `VoteInstruction::UpdateCommissionBps` instruction) is signable by the vote account's authorized withdrawer — an unprivileged key, not a validator identity or admin — and it neither bounds `commission_bps` to `0..=10_000` at write time nor imposes any epoch-timing delay, both of which are analogous to the "setFee" issues in the external report (no upper bound, and mutable at any time without a timelock).

### Finding Description
`update_commission_bps` in [1](#0-0)  stores whatever `u16` value is passed for `commission_bps` directly into `inflation_rewards_commission_bps` / `block_revenue_commission_bps` with an explicit comment "No commission update rule, per SIMD-0249 and SIMD-0291," in contrast to the legacy `update_commission` function which enforces `is_commission_update_allowed` (a "first half of epoch" delay rule) as seen at [2](#0-1) .

Test code explicitly documents that values above 10,000 bps (100%) are accepted at the program/storage level: "Values > 10,000 bps are allowed at program level. Capping happens during reward calculation, not storage." — [3](#0-2) , and the processor-side round trip test confirms updates of 150% and 500% succeed with no timing restriction at all, going back and forth freely: [4](#0-3) .

The instruction dispatcher in `vote_processor.rs` only gates the instruction on feature-activation flags (`commission_rate_in_basis_points`, `delay_commission_updates`) and, for the `BlockRevenue` kind, on `block_revenue_sharing`; it performs no bound or timing check on `commission_bps` itself: [5](#0-4) .

The only "delay" that exists for inflation-rewards commission is applied indirectly at reward-calculation time, by reading a stale/snapshot vote-account state when `delay_commission_updates` is set: [6](#0-5) . This delay logic exists only for the `InflationRewards` commission path; the `BlockRevenue` commission kind (`CommissionKind::BlockRevenue`) is written to `block_revenue_commission_bps` by the exact same unrestricted `update_commission_bps` function with no equivalent snapshot/lookback protection visible in `calculate_block_reward` ( [7](#0-6) ), meaning a withdrawer can raise block-revenue commission instantaneously and it is not evidently deferred by an epoch boundary the way `InflationRewards` commission is.

### Impact Explanation
Because commission is capped only at *reward-calculation time* (`commission_split_preserve_lamports`/`commission_split` clamp to `MAX_BPS = 10_000`, see [8](#0-7) ) rather than at write time, the maximum realized economic harm to delegators is bounded to 100% commission — this differs from the external report's raw "unbounded fee" concern, which is mitigated here. However, the removal of any timing restriction for `update_commission_bps` (unlike the legacy percentage-based `update_commission`, which enforces a delay via `is_commission_update_allowed`) reproduces the report's core concern #3: a withdrawer can raise commission immediately before a reward/distribution event, effectively "front-running" delegators' already-accrued stake rewards, taking up to 100% of rewards that delegators expected to receive at a lower rate — with no timelock giving stakers time to react (e.g., by un-delegating). This is an economic/fairness issue affecting stake reward distribution, not a fund-conservation or consensus-divergence bug, since all validators would compute this identically and lamport conservation is preserved.

### Likelihood Explanation
The `UpdateCommissionBps` instruction is directly reachable by any transaction signed by a vote account's authorized withdrawer key — a normal, unprivileged signer, gated only by feature-activation status (`commission_rate_in_basis_points`, `delay_commission_updates`, and for block revenue, `block_revenue_sharing`). No special network or leader privilege is required, and the transaction is a single top-level vote-program instruction.

### Recommendation
Given the code explicitly documents this as intentional post-SIMD-0249/SIMD-0291 design (removing the old "first half of epoch" restriction because bounded commission redemption already relies on delayed reads of vote state at reward-calculation time for `InflationRewards`), the residual risk is specifically the `BlockRevenue` commission path, which does not appear to benefit from the same delayed-lookback protection. It should be verified whether `block_revenue_commission_bps` reads in `calculate_block_reward`/its distribution path use a similarly delayed snapshot; if not, the same one-epoch delay mechanism used for `InflationRewards` commission should be applied to `BlockRevenue` commission changes.

### Proof of Concept
Not applicable as a standalone PoC beyond the referenced test code, which already demonstrates the unrestricted behavior: `test_update_commission_bps` in [9](#0-8)  shows commission being freely raised/lowered "back and forth" with no timing check, including to values of 150% and 500% bps, and `test_set_inflation_rewards_commission_bps` in [3](#0-2)  confirms values beyond 10,000 bps are accepted and persisted at the account-state level.

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

**File:** programs/vote/src/vote_state/mod.rs (L1812-1935)
```rust
    #[test]
    fn test_update_commission_bps() {
        let target_version = VoteStateTargetVersion::V4;
        let mut vote_state = vote_state_new_for_test(&solana_pubkey::new_rand(), target_version);
        let withdrawer_pubkey = *vote_state.authorized_withdrawer();
        let node_pubkey = *vote_state.node_pubkey();

        // Set initial commission.
        vote_state.set_commission(10); // 10%

        let serialized = vote_state.serialize();
        let serialized_len = serialized.len();
        let rent = Rent::default();
        let lamports = rent.minimum_balance(serialized_len);
        let mut vote_account = AccountSharedData::new(lamports, serialized_len, &id());
        vote_account.set_data_from_slice(&serialized);

        let processor_account = AccountSharedData::new(0, 0, &solana_sdk_ids::native_loader::id());
        let mut transaction_context = TransactionContext::new(
            vec![(id(), processor_account), (node_pubkey, vote_account)],
            rent,
            0,
            0,
            1,
        );
        transaction_context
            .configure_top_level_instruction_for_tests(
                0,
                vec![InstructionAccount::new(1, false, true)],
                vec![],
            )
            .unwrap();
        let instruction_context = transaction_context.get_next_instruction_context().unwrap();
        let mut borrowed_account = instruction_context
            .try_borrow_instruction_account(0)
            .unwrap();

        let signers: HashSet<Pubkey> = vec![withdrawer_pubkey].into_iter().collect();
        let non_signers: HashSet<Pubkey> = HashSet::new();

        // `CommissionKind::BlockRevenue` returns `InvalidInstructionData` when
        // block_revenue_sharing is disabled.
        assert_eq!(
            update_commission_bps(
                &mut borrowed_account,
                target_version,
                500,
                CommissionKind::BlockRevenue,
                &signers,
                false, // block_revenue_sharing disabled
            ),
            Err(InstructionError::InvalidInstructionData)
        );

        // Missing signature returns `MissingRequiredSignature`.
        assert_eq!(
            update_commission_bps(
                &mut borrowed_account,
                target_version,
                500,
                CommissionKind::InflationRewards,
                &non_signers,
                false,
            ),
            Err(InstructionError::MissingRequiredSignature)
        );

        // Incorrect signature for withdraw authority returns `MissingRequiredSignature`.
        let wrong_signers: HashSet<Pubkey> = vec![Pubkey::new_unique()].into_iter().collect();
        assert_eq!(
            update_commission_bps(
                &mut borrowed_account,
                target_version,
                500,
                CommissionKind::InflationRewards,
                &wrong_signers,
                false,
            ),
            Err(InstructionError::MissingRequiredSignature)
        );

        let mut commission_bps_roundtrip = |new_commission_bps: u16| {
            update_commission_bps(
                &mut borrowed_account,
                target_version,
                new_commission_bps,
                CommissionKind::InflationRewards,
                &signers,
                false,
            )
            .unwrap();
            update_commission_bps(
                &mut borrowed_account,
                target_version,
                new_commission_bps,
                CommissionKind::BlockRevenue,
                &signers,
                true,
            )
            .unwrap();
            let handler =
                get_vote_state_handler_checked(&borrowed_account, target_version).unwrap();
            assert_eq!(
                handler.as_ref_v4().inflation_rewards_commission_bps,
                new_commission_bps
            );
            assert_eq!(
                handler.as_ref_v4().block_revenue_commission_bps,
                new_commission_bps
            );
        };

        // There's no timing check for SIMD-0291, so just go back and forth
        // with new values.

        commission_bps_roundtrip(1_100); // Increase to 11%
        commission_bps_roundtrip(5_000); // Increase to 50%
        commission_bps_roundtrip(4_400); // Decrease to 44%
        commission_bps_roundtrip(4_600); // Increase to 46%

        // Values > 10,000 bps are allowed at program level.
        commission_bps_roundtrip(15_000); // 150%
        commission_bps_roundtrip(50_000); // 500%
    }
```

**File:** programs/vote/src/vote_state/handler.rs (L1755-1775)
```rust
    #[test]
    fn test_set_inflation_rewards_commission_bps() {
        let mut handler = VoteStateHandler::new_v4(VoteStateV4::default());

        // First test some "normal" values.
        for bps in [0, 100, 500, 1_000, 5_000, 10_000] {
            handler.set_inflation_rewards_commission_bps(bps);
            let v4 = handler.as_ref_v4();
            assert_eq!(v4.inflation_rewards_commission_bps, bps);
            // commission() should return bps / 100
            assert_eq!(handler.commission(), (bps / 100) as u8);
        }

        // Now test values > 10,000 are allowed at program level.
        // Capping happens during reward calculation, not storage.
        for bps in [10_001, 15_000, u16::MAX] {
            handler.set_inflation_rewards_commission_bps(bps);
            let v4 = handler.as_ref_v4();
            assert_eq!(v4.inflation_rewards_commission_bps, bps);
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

**File:** runtime/src/inflation_rewards/mod.rs (L377-435)
```rust
fn commission_split(commission_bps: u16, on: u64) -> (u64, u64, bool) {
    const MAX_BPS: u16 = 10_000;
    const MAX_BPS_U128: u128 = MAX_BPS as u128;
    match commission_bps.min(MAX_BPS) {
        0 => (0, on, false),
        MAX_BPS => (on, 0, false),
        split => {
            let on = u128::from(on);
            // Calculate mine and theirs independently and symmetrically instead of
            // using the remainder of the other to treat them strictly equally.
            // In Tower, this is also to cancel the rewarding if either of the parties
            // should receive only fractional lamports, resulting in not being rewarded at all.
            // Thus, note that we intentionally discard any residual fractional lamports.
            let mine = on
                .checked_mul(u128::from(split))
                .expect("multiplication of a u64 and u16 should not overflow")
                / MAX_BPS_U128;
            let theirs = on
                .checked_mul(u128::from(
                    MAX_BPS
                        .checked_sub(split)
                        .expect("commission cannot be greater than MAX_BPS"),
                ))
                .expect("multiplication of a u64 and u16 should not overflow")
                / MAX_BPS_U128;

            (mine as u64, theirs as u64, true)
        }
    }
}

/// returns commission split as (voter_portion, staker_portion, was_split) tuple,
/// assigning any fractional-lamport remainder to the voter so no lamports are lost.
///
/// This is used only for non-Tower epochs, where small unfair splits no longer defer redemption.
#[cfg_attr(any(test, feature = "dev-context-only-utils"), qualifiers(pub(crate)))]
fn commission_split_preserve_lamports(commission_bps: u16, on: u64) -> (u64, u64, bool) {
    const MAX_BPS: u16 = 10_000;
    const MAX_BPS_U128: u128 = MAX_BPS as u128;
    match commission_bps.min(MAX_BPS) {
        0 => (0, on, false),
        MAX_BPS => (on, 0, false),
        split => {
            let staker_bps = MAX_BPS
                .checked_sub(split)
                .expect("commission cannot be greater than MAX_BPS");
            let staker_rewards = u128::from(on)
                .checked_mul(u128::from(staker_bps))
                .expect("multiplication of a u64 and u16 should not overflow")
                / MAX_BPS_U128;
            let staker_rewards = staker_rewards as u64;
            let voter_rewards = on
                .checked_sub(staker_rewards)
                .expect("staker rewards cannot exceed total rewards");

            (voter_rewards, staker_rewards, true)
        }
    }
}
```
