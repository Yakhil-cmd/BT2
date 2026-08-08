### Title
Vote account commission collectors (`inflation_rewards_collector` / `block_revenue_collector`) are not reset when withdraw authority is reassigned - ([File: programs/vote/src/vote_state/mod.rs])

### Summary
`VoteStateV4` decouples "who controls the vote account" (`authorized_withdrawer`) from "who gets paid the validator's commission" (`inflation_rewards_collector`, `block_revenue_collector`), similar to how the reported `LienToken` decouples `ownerOf` from `payee`. The collector fields can be set by the current `authorized_withdrawer` via `UpdateCommissionCollector`, but when withdraw authority is later reassigned to a new owner (e.g. sale/handoff of a validator's vote account) via `VoteAuthorize::Withdrawer`, the collector fields are left untouched, so commission continues flowing to whatever address the *previous* withdraw authority configured.

### Finding Description
`authorize()` handles `VoteAuthorize::Withdrawer` by simply verifying the current withdrawer and overwriting it — it never touches the commission-collector fields: [1](#0-0) 

The collector fields are set independently, guarded only by a signature check against whichever `authorized_withdrawer` is active *at the time of the call*: [2](#0-1) 

At reward-distribution time, the commission payout target is read directly from these vote-state fields, independent of the current `authorized_withdrawer`: [3](#0-2) 

This is the exact bug class described in the external report: an "owner" (here, the withdraw authority) sets a payee (commission collector) for themselves or a controlled account, then the underlying asset's control (withdraw authority) is transferred to a new owner. Because the collector is never cleared/reset as part of the `Authorize`/`AuthorizeChecked` (Withdrawer) instruction, the new owner unknowingly continues paying commission to the old owner's address until they discover the issue and explicitly call `UpdateCommissionCollector` themselves.

### Impact Explanation
Validator commission (a share of inflation rewards and, under `block_revenue_sharing`, block revenue) is real lamports paid out every epoch/block. If a vote account's withdraw authority changes (a routine and unprivileged action a stake-pool operator, custodian, or validator business can be tricked or coerced into performing, or that naturally occurs on sale/handoff of a validator's vote account), any commission collector previously set by the old operator keeps receiving those lamports. This is a concrete misattribution/diversion of already-produced protocol rewards to an address the new legitimate controller of the vote account did not choose and may not even know exists, closely matching the "misattributed or duplicated rewards" acceptance criterion.

### Likelihood Explanation
`UpdateCommissionCollector` requires only the current `authorized_withdrawer`'s signature and does not require the new withdrawer's opt-in, so any validator/vote-account controller can pre-set an arbitrary collector before selling or delegating custody of the vote account. Because this is entirely within normal, permitted vote-program instruction flows (no privileged/validator-role assumptions beyond normal withdraw authority — the same authority a legitimate buyer would expect to also control payouts), the scenario is straightforward to trigger and requires no consensus-level compromise. It gates on the `custom_commission_collector` feature being active for the payout side to matter, but the state field and instructions exist and are reachable in the current code.

### Recommendation
When `VoteAuthorize::Withdrawer` reassigns `authorized_withdrawer` (in `authorize()`), also reset `inflation_rewards_collector` and `block_revenue_collector` back to the vote account's own pubkey (the safe default), forcing the new withdraw authority to explicitly opt back into a custom collector via `UpdateCommissionCollector` if desired — mirroring the suggested fix of clearing the stale `payee` on `LienToken` transfer.

### Proof of Concept
1. Vote account `V` has `authorized_withdrawer = A`.
2. `A` calls `UpdateCommissionCollector(InflationRewards)` setting `inflation_rewards_collector = C`, an account `A` controls (see `update_commission_collector`, `programs/vote/src/vote_state/mod.rs:907-933`).
3. `A` transfers control of `V` by calling `Authorize`/`AuthorizeChecked` with `VoteAuthorize::Withdrawer` to set `authorized_withdrawer = B` (new legitimate owner) — this instruction does not touch the collector fields (`programs/vote/src/vote_state/mod.rs:727-731`).
4. Every subsequent epoch, `calculate_stake_rewards_and_commissions` → `redeem_delegation_rewards` pays the vote account's inflation-reward commission to `commission_pubkey = inflation_rewards_collector = C` rather than to `B` or `V` (`runtime/src/bank/partitioned_epoch_rewards/calculation.rs:750-757`), diverting lamports to `A`'s address `C` even though `A` no longer controls the vote account.

### Citations

**File:** programs/vote/src/vote_state/mod.rs (L727-731)
```rust
        VoteAuthorize::Withdrawer => {
            // current authorized withdrawer must say "yay"
            verify_authorized_signer(vote_state.authorized_withdrawer(), signers)?;
            vote_state.set_authorized_withdrawer(*authorized);
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

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L744-757)
```rust
            Ok((stake_reward, commission_lamports, stake)) => {
                let inflation = InflationReward {
                    stake,
                    stake_reward,
                    commission_bps: (!custom_commission_collector).then_some(commission_bps),
                };
                let (commission_pubkey, is_vote_account) = if custom_commission_collector {
                    let commission_pubkey = *vote_state
                        .inflation_rewards_collector()
                        .unwrap_or(&vote_pubkey);
                    (commission_pubkey, commission_pubkey == vote_pubkey)
                } else {
                    (vote_pubkey, true)
                };
```
