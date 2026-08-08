### Title
Block-revenue commission (`UpdateCommissionBps`, `CommissionKind::BlockRevenue`) can be changed instantly with no epoch-delay protection, unlike inflation-rewards commission - (File: `programs/vote/src/vote_state/mod.rs`)

### Summary
The vote program's SIMD-0291 `UpdateCommissionBps` instruction lets the authorized withdrawer change either `inflation_rewards_commission_bps` or `block_revenue_commission_bps` at any slot, with no epoch-position restriction, and the new value is written to on-chain state immediately. [1](#0-0)  For the legacy percentage commission, and for `inflation_rewards_commission_bps` specifically, the runtime protects unprivileged stakers from a last-minute commission change by caching vote-account state from prior epochs and using that snapshot when computing rewards. [2](#0-1)  No equivalent protection exists for `block_revenue_commission_bps` anywhere in the reward-calculation path.

### Finding Description
`update_commission_bps` explicitly documents that it enforces no timing rule at all ("No commission update rule, per SIMD-0249 and SIMD-0291"), for both `CommissionKind::InflationRewards` and `CommissionKind::BlockRevenue`. [1](#0-0)  This is confirmed by the test explicitly asserting updates are "always allowed regardless of epoch position." [3](#0-2) 

This mirrors the reported analog exactly: like `Auction.sol`'s `setReservePrice`/`setMinimumBidIncrement`, which take effect immediately on an in-progress auction with no cooldown, `update_commission_bps` lets a validator operator change its commission mid-epoch and have that new value take effect immediately in the vote account.

The critical asymmetry is in how the two commission kinds are subsequently consumed for reward distribution. When computing `InflationRewards` (inflation staking rewards), `calculate_stake_rewards_and_commissions`/`redeem_delegation_rewards` deliberately look back at `snapshot_epoch_vote_accounts`/`rewarded_epoch_vote_accounts` (state cached from up to two epochs prior) whenever `delay_commission_updates` is active, specifically to "prevent last minute commission rugs": [4](#0-3) [2](#0-1) 

However, `calculate_block_reward` — the function that distributes the `BlockRevenue`-sourced `pending_delegator_rewards` to stake accounts — reads `pending_delegator_rewards` directly from the current `distribution_epoch_vote_accounts` view and proportionally splits it by stake with no reference to any snapshot/cached commission or delay mechanism whatsoever: [5](#0-4) 

Since `deposit_delegator_rewards` (the SIMD-0123 instruction that funds `pending_delegator_rewards`) simply adds the deposited lamports to the field without any embedded delay logic either, [6](#0-5)  the `block_revenue_commission_bps` value governing how much of a validator's block-revenue is withheld as commission versus passed to delegators can be changed instantly and is applied at whatever value is current at the moment revenue is deposited/attributed — with none of the one-epoch delay protection that the codebase itself acknowledges is necessary to stop "last minute commission rugs" for the inflation-reward case.

### Impact Explanation
A validator operator can lower `block_revenue_commission_bps` to induce delegators to keep/increase stake, then raise it back to capture a larger share of block-revenue rewards immediately upon the next distribution cycle, with zero warning period for delegators. Because no epoch-delay or snapshot mechanism guards this specific commission kind (unlike `inflation_rewards_commission_bps`), stakers' expected proportional reward split can be silently and instantly altered, resulting in misattributed rewards between the vote account (validator) and delegator-stake accounts — directly matching the accepted impact class of "misattributed or duplicated rewards."

### Likelihood Explanation
The change requires only a signature from the vote account's `authorized_withdrawer` — a normal, always-available capability of any validator operator, no special network conditions or races needed. Given the instruction explicitly disables any timing check ("No commission update rule"), this can be triggered by a single transaction at any slot, immediately prior to a block-revenue deposit/distribution, making exploitation straightforward for any validator wishing to maximize its take at delegators' expense.

### Recommendation
Apply the same epoch-delay/snapshotting protection used for `inflation_rewards_commission_bps` (via `delay_commission_updates`/cached `epoch_stakes` vote-account views) to `block_revenue_commission_bps` as well, so that a change to the block-revenue commission rate only takes effect for rewards computed from a subsequent epoch, rather than immediately affecting in-flight or upcoming block-revenue distributions.

### Proof of Concept
1. Validator operator calls `VoteInstruction::UpdateCommissionBps { commission_bps: 0, kind: CommissionKind::BlockRevenue }`, succeeding unconditionally per `update_commission_bps`. [1](#0-0) 
2. Delegators observe the low commission and delegate/maintain stake.
3. Immediately before the next block-revenue deposit/distribution cycle, the operator calls `UpdateCommissionBps` again setting `block_revenue_commission_bps` to a high value (e.g., 10000 bps = 100%).
4. `calculate_block_reward` reads the current (just-changed) vote state with no historical snapshot check, applying the new high commission rate to the entire `pending_delegator_rewards` split for that distribution. [5](#0-4) 
5. Delegators' expected reward share is unexpectedly reduced with no advance notice, contrary to the one-epoch delay guarantee that exists for `inflation_rewards_commission_bps`.

### Citations

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

**File:** programs/vote/src/vote_state/mod.rs (L1806-1817)
```rust
    /// Test update_commission_bps (SIMD-0291).
    ///
    /// Unlike test_update_commission, SIMD-0291 has no timing restrictions
    /// (per SIMD-0249). Updates are always allowed regardless of epoch position.
    ///
    /// This test only uses V4 since SIMD-0291 depends on SIMD-0185 (VoteStateV4).
    #[test]
    fn test_update_commission_bps() {
        let target_version = VoteStateTargetVersion::V4;
        let mut vote_state = vote_state_new_for_test(&solana_pubkey::new_rand(), target_version);
        let withdrawer_pubkey = *vote_state.authorized_withdrawer();
        let node_pubkey = *vote_state.node_pubkey();
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

**File:** runtime/src/bank.rs (L1723-1748)
```rust
    /// Get cached vote account state from the past few epochs so that some vote
    /// state configuration changes are delayed before being used in reward
    /// calculation.
    fn get_cached_vote_accounts<'a>(
        &'a self,
        rewarded_epoch: Epoch,
        distribution_epoch_vote_accounts: &'a VoteAccounts,
    ) -> CachedVoteAccounts<'a> {
        // Snapshot of vote account state from the beginning of the epoch prior to
        // the rewarded epoch. This snapshot state is saved a full epoch before
        // being used to prevent last minute commission rugs.
        let snapshot_epoch_vote_accounts = self
            .epoch_stakes(rewarded_epoch)
            .map(|epoch_stakes| epoch_stakes.stakes().vote_accounts());

        // Vote account state from the beginning of the rewarded epoch.
        let rewarded_epoch_vote_accounts = self
            .epoch_stakes(self.epoch())
            .map(|epoch_stakes| epoch_stakes.stakes().vote_accounts());

        CachedVoteAccounts {
            snapshot_epoch_vote_accounts,
            rewarded_epoch_vote_accounts,
            distribution_epoch_vote_accounts,
        }
    }
```
