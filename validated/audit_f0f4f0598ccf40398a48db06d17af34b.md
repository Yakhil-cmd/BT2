Based on my research, I found a concrete analog to this bug class in Agave's vote/reward accounting.

### Title
Commission-bps updates lack the epoch-boundary timing restriction applied to legacy commission, enabling retroactive theft of an entire epoch's staking rewards - (File: `programs/vote/src/vote_state/mod.rs`, `runtime/src/bank/partitioned_epoch_rewards/calculation.rs`)

### Summary
Agave's stake-reward calculation redeems an entire epoch's worth of inflation rewards at once, using whatever commission rate is observed for the vote account at the time rewards are calculated (start of the following epoch). Like StRSR's `rewardRatio`/`rewardPeriod`, a vote account's commission is a "rate" that determines how a stream of already-earned value (stake credits accrued over the epoch) gets split between the validator and its delegators. The mitigation Agave uses is to defer/"delay" the effect of a commission change by reading the commission from a prior epoch's snapshot (`delay_commission_updates`) and, for the legacy percentage field, to additionally block updates during the second half of an epoch via `is_commission_update_allowed`. However, the newer basis-points commission-update instruction (`UpdateCommissionBps`, SIMD-0291/SIMD-0123) explicitly removes the timing restriction.

### Finding Description
`update_commission` (legacy, percentage-based) enforces `is_commission_update_allowed(clock.slot, epoch_schedule)` whenever the new commission is an increase, blocking commission increases in roughly the second half of the epoch: [1](#0-0) 

`update_commission_bps`, the newer basis-points setter, intentionally has **no such rule**, per the comment "No commission update rule, per SIMD-0249 and SIMD-0291": [2](#0-1) 

At epoch-boundary reward calculation, `redeem_delegation_rewards` picks the commission to apply to the *entire* just-completed epoch's stake rewards. This is only protected from being read "live" (i.e., picking up a commission change made near the end of the rewarded epoch) when the `delay_commission_updates` feature is active, in which case it looks back at a snapshot from 1-2 epochs prior instead of the current vote state: [3](#0-2) 

If `delay_commission_updates` is not active for a given cluster/epoch (e.g., prior to activation, or in any environment where this feature has not yet been enabled), the `else` branches at lines 720-724 use the vote account's **current** commission (bps or legacy) directly — i.e., whatever commission is set on the vote account at the moment rewards are computed for the entire preceding epoch. Because `update_commission_bps` has no timing restriction, a validator can leave commission at 0 bps for the whole epoch (attracting/retaining delegators and accumulating maximum vote credits), then submit `UpdateCommissionBps` with `commission_bps = 10000` (100%) in the last slot before the epoch boundary reward-calculation snapshot is taken, and have that 100% commission applied retroactively to the entire epoch's stake rewards it already earned — exactly the "should accrue before change" failure mode described in the external report, where a change to the reward-rate "slope" is applied to an already-completed accrual period instead of only prospectively.

### Impact Explanation
This results in misattributed/stolen rewards: an entire epoch's inflation stake rewards that were rightfully earned by delegators (based on activity/points already accrued under a low commission) are redirected to the validator's commission account instead, with no way for stakers to react (the redemption uses the vote account state at the reward-calculation snapshot, not at each point in time during the epoch). This falls squarely within the "misattributed or duplicated rewards" impact category described in the task.

### Likelihood Explanation
Likelihood depends entirely on whether `delay_commission_updates` is active for the target cluster/epoch. I was not able to determine from the indexed code whether this feature is currently active on mainnet-beta/testnet, is still pending activation, or is permanently gated only for legacy `commission` semantics but was overlooked for the newer bps path introduced by SIMD-0291. If the feature is inactive, the likelihood is high and requires no special privileges beyond controlling a vote account's authorized withdrawer — an unprivileged, permissionless action available to any validator operator. If the feature is universally active, this specific path is already mitigated (the snapshot-based commission lookup at lines 709-719 applies uniformly to both bps and legacy paths when `delay_commission_updates == true`).

### Recommendation
Apply the same `is_commission_update_allowed`-style timing restriction (or equivalent activation-epoch delay) to `update_commission_bps`/`UpdateCommissionBps`, independent of `delay_commission_updates` feature-gate status, so that no commission-rate change (legacy or bps) can affect rewards for stake that was already accrued under the previous rate. Verify and, if necessary, backstop the `delay_commission_updates` feature's activation status to ensure the retroactive-application window described above cannot currently be exploited.

### Proof of Concept
1. Validator ensures `delay_commission_updates` is inactive for the target cluster (or targets an environment/epoch prior to its activation).
2. At epoch `N` start, validator sets `inflation_rewards_commission_bps = 0` via `UpdateCommissionBps` (`programs/vote/src/vote_state/mod.rs:828-859`), attracting stake and accruing full epoch credits at 0% commission.
3. Immediately before the epoch-`N`→`N+1` boundary (when `compute_new_epoch_caches_and_rewards`/`calculate_rewards` reads vote state — `runtime/src/bank.rs:1750-1813`), validator submits another `UpdateCommissionBps` setting `commission_bps = 10000` (100%). Because `update_commission_bps` has no `is_commission_update_allowed` check, this transaction is accepted at any slot in the epoch.
4. At the epoch boundary, `redeem_delegation_rewards` computes `commission_bps` via the `else if commission_rate_in_basis_points` branch, reading the just-updated 100% value (`runtime/src/bank/partitioned_epoch_rewards/calculation.rs:720-724`), and the entire epoch's stake reward is routed to the validator's commission account instead of delegators.

### Citations

**File:** programs/vote/src/vote_state/mod.rs (L806-816)
```rust
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

**File:** programs/vote/src/vote_state/mod.rs (L842-847)
```rust
    let mut vote_state = get_vote_state_handler_checked(vote_account, target_version)?;

    // No commission update rule, per SIMD-0249 and SIMD-0291.

    // Require authorized withdrawer to sign.
    verify_authorized_signer(vote_state.authorized_withdrawer(), signers)?;
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
