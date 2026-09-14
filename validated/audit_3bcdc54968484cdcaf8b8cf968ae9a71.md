### Title
Unbounded per-delegation block-revenue reward can exceed a vote account's `pending_delegator_rewards` pool during Alpenglow reward recalculation — ([File: runtime/src/bank/partitioned_epoch_rewards/calculation.rs])

### Summary
`calculate_block_reward()` computes each stake account's share of a vote account's `pending_delegator_rewards` pool as `pending_delegator_rewards * stake / total_active_stake`, clamping only the *individual* result to `pending_delegator_rewards`. There is no clamp on the **sum** of block rewards paid out across all delegations to the same vote account. The function's own comment acknowledges that `stake` can exceed `total_active_stake` during recalculation, which is exactly the "amounts computed independently from percentages/ratios instead of derived from a running total" pattern flagged in the external report (`split.totalRewards` vs. sum of `split.amounts[i]`). [1](#0-0) 

### Finding Description
`calculate_block_reward` is called once per stake delegation inside `calculate_stake_rewards_and_commissions`, in the hot reward-calculation loop that runs during Alpenglow reward accounting (SIMD-0123): [2](#0-1) 

For each delegation it computes:
```
(pending_delegator_rewards as u128 * stake as u128 / total_active_stake as u128)
    .try_into().unwrap_or(u64::MAX)
    .min(pending_delegator_rewards)
```
`total_active_stake` is read once from `reward_epoch_delegated_stakes.delegated_stakes` for the vote account, while `stake` is derived per-delegation via `delegation.stake_v2(...)`. The comment directly above explicitly states:

> "During recalculation, if stake account has already received rewards, it's possible to have `stake > total_active_stake`... We can also have individual rewards look greater than the pending rewards. This is harmless in practice, but we clamp it just to be safe" [3](#0-2) 

The clamp (`.min(pending_delegator_rewards)`) only guarantees no single delegation's `block_reward` exceeds the pool — it does **not** guarantee that the sum of `block_reward` across *all* delegations to that vote account stays within `pending_delegator_rewards`. If, as the comment admits, multiple delegations can individually compute `stake_i > total_active_stake` (because `stake_i` and `total_active_stake` are sourced from different snapshots — one from live `stake_history`/warmup-adjusted delegation state, the other from a cached `RewardEpochDelegatedStakes` map), then each of those delegations' `block_reward` can independently be clamped up to the full `pending_delegator_rewards` value. Summed over N such delegations, the vote account could be credited up to `N × pending_delegator_rewards` in block rewards, i.e., lamports minted well beyond what the account's `pending_delegator_rewards` pool represents. This is the direct structural analog of the Sherlock finding: each recipient's share is computed from a ratio against a denominator that does not equal the true sum of numerators, so the parts no longer reconcile with the total.

I was not able to fully trace, within the remaining budget, whether `distribution.rs` performs a final checked/saturating decrement of `pending_delegator_rewards` per stake account that would turn this into a hard error (revert/panic → DOS) versus an unchecked/saturating decrement that would allow silent over-minting (fund creation) — the `distribution.rs` file has 48 references to `block_reward`/`pending_delegator_rewards` that I could not read line-by-line before running out of tool calls. Both outcomes described in the report style are plausible here:
- If the decrement of `pending_delegator_rewards` on the vote account is a **checked** subtraction that panics/errors on underflow, this becomes a validator-crash / cluster-halt vector once a vote account's stake accounts drift into the `stake > total_active_stake` state (reachable purely through normal stake activation/deactivation/redelegation over epochs — not through direct attacker-crafted transactions, which is a weakness for the "unprivileged transaction sender" requirement).
- If it is **not** checked, delegators can be credited more lamports than the vote account's actual accrued block revenue, which is uncontrolled lamport creation.

### Impact Explanation
If the unchecked-mint variant holds, this is a direct violation of lamport conservation/capitalization accounting during Alpenglow's SIMD-0123 block-revenue-sharing reward distribution — a "concrete unsigned fund movement or minting" class issue, which is explicitly in scope per the validation rules. If the checked-panic variant holds instead, a deterministic state (reachable via ordinary stake delegation actions across epochs, not a single malicious transaction) triggers an assert/panic on all validators simultaneously — a cluster-halt class issue.

### Likelihood Explanation
Low-to-Medium. This requires reward *recalculation* to occur (i.e., an epoch boundary recalculation path) combined with a vote account whose set of delegations, taken together, produce `stake_i > total_active_stake` for enough delegations that their clamped block rewards sum meaningfully above `pending_delegator_rewards`. The code comment states this condition ("it's possible to have `stake > total_active_stake`") is a known, reachable state during recalculation, not a theoretical one — but I could not confirm from the available context how large the aggregate divergence can practically get, nor whether downstream code in `distribution.rs` neutralizes the effect (e.g., by tracking a separate running total and clamping there, or by using saturating arithmetic that just discards the overpay without crashing or minting).

### Recommendation
Given the acknowledged possibility that `stake > total_active_stake` per delegation, `calculate_block_reward` (and its caller `calculate_stake_rewards_and_commissions`) should track a running total of block rewards already assigned per vote account and clamp each subsequent delegation's `block_reward` to `pending_delegator_rewards.saturating_sub(running_total)`, rather than clamping each delegation independently against the full, un-decremented `pending_delegator_rewards`. Additionally, `distribution.rs`'s handling of the vote account's `pending_delegator_rewards` decrement should be audited to confirm it uses saturating (not panicking) arithmetic, and that any shortfall/overpay condition is logged/metriced rather than causing divergent or crashing behavior across the fleet.

### Proof of Concept
Not fully constructible from the indexed context: reproducing this requires driving a vote account into the epoch-boundary recalculation path (`recalculate_stake_rewards` / `AlpenglowEpochType::MigrationEpoch`/`Alpenglow` recalculation) with multiple delegations such that `stake_v2(...)` for each delegation, computed against `stake_history`, exceeds the single cached `total_active_stake` from `RewardEpochDelegatedStakes` — as acknowledged directly in the code's own comment at [4](#0-3) . A concrete PoC would need to instrument `test_recalculate_stake_rewards`/`test_recalculate_partitioned_rewards` (present in the same file) to assert that `sum(block_reward for all delegations to vote_pubkey) <= pending_delegator_rewards`, and show that assertion fails for a constructed multi-delegation scenario. I could not complete this construction and verify `distribution.rs`'s downstream handling within the available tool budget, so this finding should be treated as requiring further confirmation before being considered conclusively proven.

### Citations

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L172-228)
```rust
/// Calculates block reward for a stake account based on SIMD-0123
fn calculate_block_reward(
    rewarded_epoch: Epoch,
    delegation: &Delegation,
    stake_history: &StakeHistory,
    distribution_epoch_vote_accounts: &VoteAccounts,
    ag_epoch_type: &AlpenglowEpochType,
    new_warmup_cooldown_rate_epoch: Option<Epoch>,
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
        let stake = delegation.stake_v2(
            rewarded_epoch,
            stake_history,
            new_warmup_cooldown_rate_epoch,
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

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L818-831)
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
                        )
                    } else {
                        0
                    };
                    let maybe_reward_record = self.redeem_delegation_rewards(
```
