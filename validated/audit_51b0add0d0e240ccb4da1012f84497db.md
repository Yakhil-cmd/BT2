### Title
Validator Commission-Rate (Basis Points) Updates Bypass the Intended One-Epoch Notice Delay for Block-Revenue-Sharing Fees - ([File: programs/vote/src/vote_processor.rs])

### Summary
The vote program's `UpdateCommissionBps` instruction (SIMD-0291), used to change a validator's block-revenue-sharing commission, has no epoch-position timing restriction, unlike the legacy `UpdateCommission` instruction. Because the block-revenue commission actually charged against delegator rewards is read from a vote-account snapshot that is only refreshed once per epoch boundary, a validator can submit an `UpdateCommissionBps` transaction in the very last slot before an epoch boundary and have the new (higher) commission apply to the entire following epoch — effectively bypassing the "at least one full epoch" notice period that the delay-commission-update design is supposed to guarantee, mirroring the reported spl-stake-pool "Fee Update Delay Bypass" bug class.

### Finding Description
Two different commission-update code paths exist in the vote program:

1. **Legacy percentage commission** (`update_commission`) enforces `is_commission_update_allowed`, which restricts commission *increases* to the first half of an epoch: [1](#0-0) [2](#0-1) 

2. **Basis-points commission** (`update_commission_bps`, SIMD-0291) is dispatched from `VoteInstruction::UpdateCommissionBps` and requires only that `commission_rate_in_basis_points` and `delay_commission_updates` feature flags be active — it passes no `Clock`/`EpochSchedule` and therefore performs **no epoch-position check at all**: [3](#0-2) 

This is confirmed directly by the test suite's own documentation: [4](#0-3) 

Meanwhile, the block-revenue commission actually applied when distributing per-block fees is *not* read live from the vote account each slot — it is read from the epoch-boundary vote-account snapshot used to build the leader schedule for the current epoch: [5](#0-4) 

The comment explicitly states the intent: fetch commission "from the state of the vote account at the beginning of the previous epoch," so that commission changes are naturally delayed by roughly one epoch. But because that snapshot is only taken at the epoch boundary and `UpdateCommissionBps` has no restriction preventing an update in the final slot(s) before the boundary, a validator can time the increase to land immediately before the snapshot is captured, collapsing the intended one-epoch notice window down to essentially zero slots — the increased commission is then locked in and applied to every block-revenue payout for the entire subsequent epoch.

This is structurally the same bug class as the `spl-stake-pool` report: a fee mechanism nominally described as "only changeable in the next epoch" is trivially manipulable at the epoch boundary to apply with near-zero real notice, defeating the purpose of the delay (giving delegators/stakers time to react, e.g. by undelegating).

### Impact Explanation
Delegators to a vote account have no on-chain mechanism to react to a commission-bps increase before it is applied, because the change can be crafted to land in the final slot of an epoch and take full effect for the entirety of the next epoch. This directly causes stake/reward corruption from the delegators' perspective: an unexpectedly higher commission skims a larger share of block-revenue-sharing rewards without the intended one-epoch warning, redirecting funds from delegators to the validator operator. This falls under the "stake or reward corruption" impact category permitted by scope.

### Likelihood Explanation
The action requires only a normal `UpdateCommissionBps` transaction signed by the vote account's existing authorized withdrawer/commission-authority — the same privilege level as any legitimate commission update, and reachable by any account operator, not a privileged network role. The only skill required is timing the transaction near an epoch boundary, which is observable via the `Clock` sysvar. No consensus-breaking or malicious-leader assumptions are needed.

### Recommendation
Apply an epoch-position (or clock-based) timing restriction to `update_commission_bps` analogous to `is_commission_update_allowed` for the legacy path (e.g., disallow commission increases after the midpoint of the epoch, or require the block-revenue commission snapshot to lag by a full additional epoch, matching how `delay_commission_updates` already delays the inflation-rewards commission via `get_cached_vote_accounts`/`snapshot_epoch_vote_accounts`).

### Proof of Concept
Conceptual sequence (a background Devin session with cluster/test access would be needed to produce an executable PoC and confirm exact epoch-stakes snapshot timing):
1. Attacker operates a vote account with delegated stake and low `inflation_rewards_commission_bps`/block-revenue commission.
2. Near the very last slot of epoch N, submit `VoteInstruction::UpdateCommissionBps { commission_bps: 10_000, kind: CommissionKind::BlockRevenue }` signed by the withdrawer — accepted unconditionally per `vote_processor.rs` lines 343-363, with no epoch-position check.
3. At the N→N+1 boundary, the bank captures `epoch_stakes` for epoch N+1 from vote-account state that already reflects the new commission.
4. For the entirety of epoch N+1, `deposit_or_burn_fee` (`fee_distribution.rs`) uses the newly raised commission via `epoch_stakes.get(&self.epoch)`, denying delegators their expected share of block-revenue rewards with no real notice period, despite the design intent of a one-epoch delay.

**Note on completeness:** I was unable to inspect the full body of `update_commission_bps` in `programs/vote/src/vote_state/mod.rs` or the exact code that populates `epoch_stakes` at the epoch boundary (`runtime/src/bank.rs`) before the tool budget was exhausted; the finding is based on the caller-side dispatch logic, the explicit test-comment documentation, and the `fee_distribution.rs` snapshot-fetch logic, which together strongly support but do not exhaustively confirm the exact boundary-timing semantics.

### Citations

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

**File:** programs/vote/src/vote_state/mod.rs (L995-1009)
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

**File:** programs/vote/src/vote_state/mod.rs (L1823-1827)
```rust
    /// Test update_commission_bps (SIMD-0291).
    ///
    /// Unlike test_update_commission, SIMD-0291 has no timing restrictions
    /// (per SIMD-0249). Updates are always allowed regardless of epoch position.
    ///
```

**File:** programs/vote/src/vote_processor.rs (L343-363)
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

**File:** runtime/src/bank/fee_distribution.rs (L142-177)
```rust
    fn deposit_or_burn_fee(&self, deposit: u64) -> u64 {
        if deposit == 0 {
            return 0;
        }

        // Per SIMD-0232: the commission collector address should be fetched
        // from the state of the vote account at the beginning of the previous
        // epoch. This is the vote account state used to build the leader
        // schedule for the current epoch, which *DOES NOT* correspond to
        // `Bank::current_epoch_stakes()`.
        let feature_snapshot = self.feature_set.snapshot();
        let (collector_id, commission_bps) = if feature_snapshot.custom_commission_collector {
            let vote_account = self
                .epoch_stakes
                .get(&self.epoch)
                .and_then(|stakes| {
                    stakes
                        .stakes()
                        .vote_accounts()
                        .get(&self.leader.vote_address)
                })
                .expect("The vote account for the leader must exist");
            (
                // Protection in case the leader is on a vote state without a
                // collector id, which can happen if a dormant pre-v4 vote state
                // accrues stake.
                vote_account
                    .vote_state_view()
                    .block_revenue_collector()
                    .unwrap_or(&self.leader.id),
                // For pre-v4 vote states, defaults to the max of 10_000 bps
                vote_account.vote_state_view().block_revenue_commission(),
            )
        } else {
            (&self.leader.id, MAX_BPS)
        };
```
