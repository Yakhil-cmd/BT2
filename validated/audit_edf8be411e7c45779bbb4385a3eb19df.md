## Analysis

The vote program's SIMD-0232 "custom commission collector" feature has an asymmetric protection gap compared to its sibling commission-*rate* protection (`delay_commission_updates`), and this maps directly onto the reported bug class ("pending fee should be settled before adjusting the fee").

### Title
Commission collector changes are not delayed like commission rate changes, allowing redirection of an already-accrued epoch's commission - (File: `runtime/src/bank/partitioned_epoch_rewards/calculation.rs`)

### Summary
The vote program deliberately delays the effect of `UpdateCommission`/`UpdateCommissionBps` rate changes by a full epoch specifically to prevent "last-minute commission rugs" [1](#0-0) , implemented via a snapshot lookup in `redeem_delegation_rewards` [2](#0-1) . However, the SIMD-0232 commission *collector* (the pubkey that actually receives the commission lamports, changeable via `UpdateCommissionCollector`) is resolved from the current, non-delayed vote state rather than the delayed snapshot used for the rate [3](#0-2) .

### Finding Description
`update_commission_collector` lets the vote account's authorized withdrawer instantly repoint `inflation_rewards_collector`/`block_revenue_collector` to any valid account, with no timing restriction ("No commission update rule, per SIMD-0249 and SIMD-0291" comment on the analogous bps setter) [4](#0-3) .

At epoch-boundary reward calculation, `redeem_delegation_rewards` computes the commission rate (`commission_bps`) from a *delayed* snapshot (`snapshot_epoch_vote_accounts`) specifically to stop a validator from bumping commission right before payout and stealing the whole epoch's stake rewards [2](#0-1) . But the `commission_pubkey` (who actually receives the commission) is derived from `vote_state` — the *current*, non-delayed view obtained from `distribution_epoch_vote_accounts` — via `vote_state.inflation_rewards_collector()`: [5](#0-4) 

Since this resolution happens once, at the start of the new epoch when `calculate_stake_rewards_and_commissions` runs (before the partitioned distribution actually credits accounts), an authorized withdrawer can call `UpdateCommissionCollector` at any point up to that calculation — including in the very last slot of the rewarded epoch — and redirect the entire epoch's commission (which was earned while votes were being cast under one collector) to a brand-new collector account, with the change applying retroactively to already-accrued-but-unsettled commission.

This is the exact analog of the report: the "pending fee" (the epoch's already-earned, not-yet-distributed commission) should be settled against the collector in effect while it accrued, but instead follows whatever collector is in effect at calculation time — a distinct address, target, and amount than what accrued voters/stakers expected.

### Impact Explanation
Impact is Medium: it causes misattributed rewards — lamports that stakers/validators earned as commission for the just-completed epoch can be redirected to an attacker-controlled account chosen only in the last block(s) of that epoch, bypassing the one-epoch delay protection that the codebase explicitly built for the rate field. No lamports are minted/burned outside protocol rules (this is a diversion, not inflation), but ownership of already-earned commission lamports is misdirected.

### Likelihood Explanation
Likelihood is Medium: any vote account's authorized withdrawer (an ordinary keypair holder, not requiring special validator/consensus privilege) can trigger this simply by submitting an `UpdateCommissionCollector` instruction near an epoch boundary; the collector-account validity check (`validate_and_resolve_key`) only requires a system-owned, rent-exempt account or the vote account itself [4](#0-3) , which is trivial to satisfy.

### Recommendation
Resolve `commission_pubkey` from the same delayed snapshot (`snapshot_epoch_vote_accounts`/`rewarded_epoch_vote_accounts`) used for `commission_bps` in `redeem_delegation_rewards`, rather than from the current `distribution_epoch_vote_accounts` view, so collector changes are subject to the same one-epoch delay as rate changes.

### Proof of Concept
1. Vote account V has `inflation_rewards_collector = A` for the entire rewarded epoch E, accruing commission normally throughout.
2. In the last slot(s) of epoch E (before the epoch-boundary reward calculation runs), the authorized withdrawer submits `UpdateCommissionCollector(InflationRewards)` setting the collector to B (an account B controls), per `update_commission_collector` [4](#0-3) .
3. At the start of epoch E+1, `calculate_stake_rewards_and_commissions`/`redeem_delegation_rewards` runs, reading `vote_state.inflation_rewards_collector()` from the just-updated (non-delayed) vote state and resolves `commission_pubkey = B` [5](#0-4) .
4. The full epoch E commission — earned while A was the recorded collector — is credited to B instead of A during `load_and_reward_commission_accounts`/`distribute_reward_commissions` [6](#0-5) .

### Citations

**File:** programs/vote/src/vote_processor.rs (L205-209)
```rust
            // Disable the commission update rule after the "delay commission
            // update" feature is activated because it imposes a minimum delay
            // of one full epoch before the new commission rate takes effect.
            let disable_commission_update_rule =
                invoke_context.get_feature_set().delay_commission_updates;
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L369-390)
```rust
        // Load the commission accounts and apply their rewards.
        // This is intentionally deferred from calculation time so that any
        // intervening account mutations (e.g. VAT burns in
        // `update_epoch_stakes`) are reflected.
        let (reward_commission_accounts, load_and_reward_commission_accounts_us) =
            measure_us!(self.load_and_reward_commission_accounts(reward_commissions, thread_pool));
        rewards_metrics.load_and_reward_commission_accounts_us =
            load_and_reward_commission_accounts_us;
        info!(
            "load_and_reward_commission_accounts: input_count={} output_count={} elapsed_us={}",
            reward_commissions.len(),
            reward_commission_accounts.accounts_with_rewards.len(),
            load_and_reward_commission_accounts_us,
        );

        let RewardCommissionLamportAmounts {
            distributed_lamports,
            distributed_to_incinerator_lamports,
            burned_lamports,
        } = reward_commission_accounts.amounts;
        self.store_commission_accounts_partitioned(&reward_commission_accounts, rewards_metrics);
        self.update_reward_commissions(&reward_commission_accounts);
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L700-757)
```rust
        };
        let vote_state = vote_account.vote_state_view();

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

        match redeem_rewards(
            stake,
            commission_bps,
            DelegatedVoteState::from(vote_state),
            CalculationEnvironment {
                rewarded_epoch,
                point_value,
                stake_history,
                new_rate_activation_epoch,
                commission_rate_in_basis_points,
                adjust_delegations_for_rent,
                use_fixed_point_stake_math,
            },
            reward_calc_tracer,
            ag_epoch_type,
            current_lamports,
            minimum_lamports,
        ) {
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
