Confirmed: `set_authorized_withdrawer` simply overwrites `v4.authorized_withdrawer` and does not touch `bls_pubkey_compressed`, `inflation_rewards_collector`, or `block_revenue_collector` fields [1](#0-0) . The `authorize()` handler for `VoteAuthorize::Withdrawer` only verifies the current authorized withdrawer is a signer and then calls `set_authorized_withdrawer`, with no reset of the commission-collector fields [2](#0-1) .

### Title
Stale commission-collector configuration set by a previous authorized withdrawer is used after vote-account withdraw authority is transferred, misdirecting inflation/block-revenue rewards - (File: `programs/vote/src/vote_state/mod.rs`)

### Summary
The vote program lets the current `authorized_withdrawer` redirect reward payouts to an arbitrary "commission collector" address via `update_commission_collector` (SIMD-0232) [3](#0-2) . This collector address is stored in vote-account state (`inflation_rewards_collector` / `block_revenue_collector`) independently of the `authorized_withdrawer` field. When the withdraw authority is later reassigned via `authorize(..., VoteAuthorize::Withdrawer, ...)`, only `authorized_withdrawer` is overwritten; the collector fields are left untouched [2](#0-1) [1](#0-0) . At the next reward-distribution and fee-collection cycle, the runtime resolves the payout destination straight from this stale field without any check that it still corresponds to the current withdraw authority.

### Finding Description
`update_commission_collector` requires only the *current* authorized withdrawer's signature to set `inflation_rewards_collector` or `block_revenue_collector` to any resolved key [4](#0-3) . Separately, `update_validator_identity` conditionally re-syncs `block_revenue_collector` to `node_pubkey` only when `custom_commission_collector_enabled` is false [5](#0-4) ; once custom collectors are enabled, this sync no longer happens and the field is fully decoupled from account "ownership" (identity/withdraw authority).

Crucially, `authorize()`'s `VoteAuthorize::Withdrawer` branch — the vote-program's closest analog to "transferring ownership" of a vote account — never clears or re-validates the previously configured collector addresses [2](#0-1) . Downstream, both the epoch-reward distribution path and the per-block priority-fee distribution path fetch the collector directly from vote-account state and pay lamports to it unconditionally:
- `redeem_delegation_rewards` resolves `commission_pubkey` from `vote_state.inflation_rewards_collector()` (falling back to the vote pubkey) whenever `custom_commission_collector` is enabled, and pays commission lamports to that address [6](#0-5) .
- `deposit_or_burn_fee` resolves the block's transaction-fee collector from `vote_state_view().block_revenue_collector()` for the epoch's leader vote account [7](#0-6) .

Neither consumer checks whether the collector address was configured by the *current* authorized withdrawer versus a previous one. This exactly mirrors the reported bug class: a per-account configuration value (`positionConfigs[tokenId]` in the report) set by a prior "owner" (authorized withdrawer) is consumed by privileged runtime logic on behalf of a new owner without re-validating provenance.

### Impact Explanation
If a vote account's controlling authority (`authorized_withdrawer`) is transferred — e.g. the validator operator role or the vote account itself changes hands, a common real operation (`solana vote-authorize-withdrawer`) — the new authorized withdrawer inherits the vote account, but the previous withdrawer's chosen commission collector addresses remain in effect. Both the block-revenue (per-block fee) and inflation-rewards commission for that vote account will continue to be paid to the previous owner's chosen address rather than the new owner's, until the new owner discovers and overwrites it via `update_commission_collector`. This is a misattribution/diversion of lamport rewards away from the rightful current controller of the vote account, satisfying the "misattributed or duplicated rewards" impact criterion. Because commission accrues continuously (every epoch/every block for which the leader schedule uses this vote account), the amount misdirected can be substantial and recurring until noticed.

### Likelihood Explanation
This requires no privileged validator/operator role beyond normal use of the vote program's own public instructions (`VoteInstruction::Authorize`/`AuthorizeWithSeed` for `Withdrawer`, and `UpdateCommissionCollector` if SIMD-0232 features are active) — both are unprivileged, permissionless instructions available to any vote-account withdraw authority. The scenario naturally occurs whenever a vote account changes hands (sale/transfer of a validator's voting identity, staking-pool operator rotation, etc.) without the outgoing withdrawer being forced to reset the collector, and the new withdrawer has no signal from the on-chain program that the collector is stale. Given SIMD-0232/custom-commission-collector is a currently rolling-out feature, likelihood scales with its activation, but once active this is a straightforward, repeatable path.

### Recommendation
When `authorize()` processes `VoteAuthorize::Withdrawer`, reset `inflation_rewards_collector` and `block_revenue_collector` (and any associated basis-point overrides) to their default (i.e., back to the vote account/node pubkey) unless the *new* withdrawer explicitly re-confirms/re-sets them in the same transaction. Alternatively, track and enforce that `update_commission_collector` only remains valid if it was set by the currently active authorized withdrawer, invalidating stale collector configuration automatically whenever `authorized_withdrawer` changes, analogous to the recommended mitigation in the referenced report (binding config validity to current owner identity).

### Proof of Concept
1. Alice controls a vote account `V` (is `authorized_withdrawer`). She calls `UpdateCommissionCollector` to set `inflation_rewards_collector = Alice_alt_wallet` via `update_commission_collector` [4](#0-3) .
2. Alice sells/transfers the vote account by calling `Authorize(new_withdrawer = Bob, VoteAuthorize::Withdrawer)`. Only `authorized_withdrawer` is updated; the collector field is untouched [2](#0-1) [1](#0-0) .
3. Bob is now the sole authorized withdrawer of `V` and believes he fully controls the vote account and its rewards.
4. At the next epoch boundary, `redeem_delegation_rewards` computes inflation commission for `V` and pays it to `vote_state.inflation_rewards_collector()`, which still resolves to `Alice_alt_wallet` [6](#0-5) . Likewise, if `V` is a leader, per-block priority-fee commission is routed via `block_revenue_collector()` to Alice's address [7](#0-6) .
5. Bob receives no commission rewards despite being the current, sole authorized withdrawer, until he separately discovers and calls `update_commission_collector` himself.

*Note: I could not fully verify the exact semantics of `NewCommissionCollector::validate_and_resolve_key` (its definition lives in `programs/vote/src/vote_state/mod.rs` but I was not able to read its body before running out of tool calls), nor whether any other instruction path implicitly clears the collector fields elsewhere in the codebase. This should be verified by a maintainer/agent with full file access before treating this as conclusively unmitigated.*

### Citations

**File:** programs/vote/src/vote_state/handler.rs (L64-68)
```rust
    pub(crate) fn set_authorized_withdrawer(&mut self, authorized_withdrawer: Pubkey) {
        match &mut self.target_state {
            TargetVoteState::V4(v4) => v4.authorized_withdrawer = authorized_withdrawer,
        }
    }
```

**File:** programs/vote/src/vote_state/mod.rs (L727-731)
```rust
        VoteAuthorize::Withdrawer => {
            // current authorized withdrawer must say "yay"
            verify_authorized_signer(vote_state.authorized_withdrawer(), signers)?;
            vote_state.set_authorized_withdrawer(*authorized);
        }
```

**File:** programs/vote/src/vote_state/mod.rs (L769-794)
```rust
/// Update the node_pubkey, requires signature of the authorized voter
pub fn update_validator_identity<S: std::hash::BuildHasher>(
    vote_account: &mut BorrowedInstructionAccount,
    target_version: VoteStateTargetVersion,
    node_pubkey: &Pubkey,
    signers: &HashSet<Pubkey, S>,
    custom_commission_collector_enabled: bool,
) -> Result<(), InstructionError> {
    let mut vote_state = get_vote_state_handler_checked(vote_account, target_version)?;

    // current authorized withdrawer must say "yay"
    verify_authorized_signer(vote_state.authorized_withdrawer(), signers)?;

    // new node must say "yay"
    verify_authorized_signer(node_pubkey, signers)?;

    vote_state.set_node_pubkey(*node_pubkey);

    // Before SIMD-0232, block_revenue_collector is always synced with node_pubkey.
    // After SIMD-0232, the collector can be set independently.
    if !custom_commission_collector_enabled {
        vote_state.set_block_revenue_collector(*node_pubkey);
    }

    vote_state.set_vote_account_state(vote_account)
}
```

**File:** programs/vote/src/vote_state/mod.rs (L907-933)
```rust
/// Update the vote account's commission collector (SIMD-0232).
pub fn update_commission_collector<S: std::hash::BuildHasher>(
    vote_account: &mut BorrowedInstructionAccount,
    target_version: VoteStateTargetVersion,
    new_collector: NewCommissionCollector,
    kind: CommissionKind,
    signers: &HashSet<Pubkey, S>,
    rent: &Rent,
) -> Result<(), InstructionError> {
    let mut vote_state = get_vote_state_handler_checked(vote_account, target_version)?;

    // Require authorized withdrawer to sign.
    verify_authorized_signer(vote_state.authorized_withdrawer(), signers)?;

    let new_collector_key = new_collector.validate_and_resolve_key(vote_account, rent)?;

    match kind {
        CommissionKind::InflationRewards => {
            vote_state.set_inflation_rewards_collector(new_collector_key);
        }
        CommissionKind::BlockRevenue => {
            vote_state.set_block_revenue_collector(new_collector_key);
        }
    }

    vote_state.set_vote_account_state(vote_account)
}
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L750-757)
```rust
                let (commission_pubkey, is_vote_account) = if custom_commission_collector {
                    let commission_pubkey = *vote_state
                        .inflation_rewards_collector()
                        .unwrap_or(&vote_pubkey);
                    (commission_pubkey, commission_pubkey == vote_pubkey)
                } else {
                    (vote_pubkey, true)
                };
```

**File:** runtime/src/bank/fee_distribution.rs (L130-151)
```rust
        let feature_snapshot = self.feature_set.snapshot();
        let collector_id = if feature_snapshot.custom_commission_collector {
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
            // Protection in case the leader is on a vote state without a
            // collector id, which can happen if a dormant pre-v4 vote state
            // accrues stake.
            vote_account
                .vote_state_view()
                .block_revenue_collector()
                .unwrap_or(&self.leader.id)
        } else {
            &self.leader.id
        };
```
