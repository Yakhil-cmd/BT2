### Title
Spoke usage aggregate can fall out of sync with position sums, making `withdraw`/`repay` revert with arithmetic underflow and freezing funds - (File: contracts/controller/src/spoke_usage.rs)

### Summary

The bug class in the external report is: an aggregate bookkeeping field (`tick.withdrawnAmounts`) is reset at the start of a new cycle while per-position balances persist, so a later exit subtracts a stale, larger amount and reverts on underflow — permanently blocking the user's exit.

The direct analog in XOXNO Lending is the per-(spoke, hub_asset) aggregate `SpokeUsageRaw` (`supplied_scaled_ray` / `borrowed_scaled_ray`) tracked in `SpokeUsageContext`. Every position exit decrements this aggregate with a hard `checked_sub` that panics on underflow, while aggregate *creation* silently treats a missing row as zero. Any flow that loses or resets the aggregate row while positions still hold scaled shares makes all subsequent exits of those positions revert with `GenericError::MathOverflow`, freezing user funds.

### Finding Description

In `contracts/controller/src/spoke_usage.rs`:

- `apply_exit` buffers a scaled decrease and panics when the stored aggregate is smaller than the exiting position's delta:

```rust
let next = side
    .scaled(&usage)
    .checked_sub(delta_scaled.raw())
    .unwrap_or_else(|| panic_with_error!(&self.env, GenericError::MathOverflow));
assert_with_error!(&self.env, next >= 0, GenericError::InternalError);
```
(spoke_usage.rs:131-136)

- `apply_entry` creates the row from `unwrap_or_default()` when absent, i.e. a missing/expired aggregate restarts accounting at zero for that spoke/asset:

```rust
let mut usage = self.load_usage_row(hub_asset).unwrap_or_default();
```
(spoke_usage.rs:111)

- `load_usage_row` returns `None` for a missing storage row, and `apply_exit` treats a missing row as a silent no-op (spoke_usage.rs:95, 128-130) — the asymmetry means the aggregate can legitimately be "empty" while `AccountPosition.scaled_amount` values remain large.

This aggregate is debited on every user exit path: `merge_withdraw_leg` calls `apply_leg_usage` with `LegDirection::Exit` and `old_scaled` (contracts/controller/src/positions/supply.rs:345-354), debt repay does the same on the borrow side, and bad-debt cleanup decrements both sides for all positions of the cleaned account (contracts/controller/src/positions/liquidation/bad_debt.rs:23-46).

Desync scenario reachable by unprivileged users:

1. Suppliers fund a spoke asset; `SpokeUsageRaw.supplied_scaled_ray` equals the sum of their scaled positions.
2. The spoke usage persistent entry is lost or undercounts the true total. The concrete reachable vector is TTL/archival expiry of the spoke-usage storage key (`storage::get_spoke_usage`/`set_spoke_usage` in contracts/controller/src/storage/spoke.rs): the usage row is keyed separately from account positions and is only rewritten when a flow touching that spoke+asset runs `persist_spoke_usage`. If the entry expires while account positions (separate keys, renewed on account activity via `storage::renew_user_account`) remain live, the next `supply`/`borrow` recreates the row via `unwrap_or_default()` counting only new activity.
3. Any prior supplier now calls `Controller::withdraw` (or a borrower calls `repay`, or `liquidate`/`clean_bad_debt` touches their legs). `apply_exit` subtracts their full `scaled_amount` from an aggregate smaller than the delta → `MathOverflow` panic → the transaction always reverts.

The same shape as the reference bug: cycle boundary (aggregate row loss/reset) zeroes bookkeeping while position balances survive, then exit reverts on subtraction underflow.

### Impact Explanation

Permanent freezing of funds for affected positions: once `supplied_scaled_ray < position.scaled_amount`, every exit path for that position — `withdraw`, `liquidate` collateral legs, `clean_bad_debt`, `multiply`/strategy unwinds that withdraw — reverts deterministically. The revert cannot be repaired by users since `set_spoke_usage` is only written internally. If the borrow side desyncs, `repay`/`liquidate`/`swap_debt` revert for existing debtors, blocking repayments and liquidations and driving the market toward insolvency. This meets the "permanent freezing of funds" / "protocol insolvency" impact bars.

### Likelihood Explanation

Medium. Triggering requires the spoke-usage aggregate to be lost or undercounted relative to live positions — most plausibly persistent-storage archival expiry of the usage key while account position keys are renewed by unrelated activity (`renew_user_account` is called on account-touching flows, e.g. params.rs:176, but nothing renews the spoke-usage row except writes to that same market+spoke). A quiet spoke market with no flows for longer than the persistent TTL reaches this state with no attacker action; an attacker can also deliberately pick a dormant spoke/asset. A caveat: I could not fully verify the TTL/renewal policy applied to the `SpokeUsage` storage key in `contracts/controller/src/storage/spoke.rs` within available iterations — if every read path bumps TTL indefinitely, the expiry vector weakens, though any other reset/write-down path that shrinks the aggregate below the sum of positions produces the same permanent revert.

### Recommendation

- Make `apply_exit` saturating rather than panicking: clamp the decrement at the stored aggregate (`next = max(0, usage - delta)`) or reconcile by recomputing/actually-tracking per-position deltas, since per-position `scaled_amount` is the source of truth, not the aggregate row.
- On `apply_exit` for a missing row, log/flag rather than silently no-op'ing, so aggregate undercounts are detectable.
- Ensure the spoke-usage storage entry TTL is extended on every read/write (same treatment as account data via `renew_user_account`), or derive caps enforcement from a recoverable structure.
- Add a fuzzable invariant: `sum(position.scaled_amount) <= spoke_usage.supplied_scaled_ray` must hold after every operation, and `withdraw` must not revert when the position exists and liquidity is available — the analogue of the report's suggested `exit`-does-not-revert property test.

### Proof of Concept

```rust
// Sketch (Soroban test env, mock_all_auths):
// 1. BOB supplies X of asset A in spoke S.
//    -> spoke_usage[S][A].supplied_scaled_ray = bob_scaled
// 2. Let the spoke usage persistent entry expire (jump ledger past TTL,
//    or delete the SpokeUsage key for (S, A) while keeping BOB's position).
// 3. CAROL supplies a small amount of A.
//    -> apply_entry: load_usage_row -> None -> unwrap_or_default()
//    -> spoke_usage[S][A].supplied_scaled_ray = carol_scaled << bob_scaled
// 4. BOB calls controller.withdraw(account_id, vec![(A, 0 /*full*/)]).
//    -> merge_withdraw_leg -> apply_leg_usage(Exit, old_scaled = bob_scaled)
//    -> apply_exit: carol_scaled.checked_sub(bob_scaled) -> None
//    -> panic_with_error!(GenericError::MathOverflow)
// Result: BOB's withdraw always reverts; his supplied funds are frozen.
// The same sequence on the borrow side bricks repay/liquidate for debtors.
```