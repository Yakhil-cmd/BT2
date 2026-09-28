### Title
Permissionless `update_account_threshold` retroactively applies adverse liquidation terms to other users' positions after a spoke listing edit - (File: contracts/controller/src/risk/params.rs)

### Summary
Each supply position stamps `loan_to_value`, `liquidation_threshold`, `liquidation_bonus`, and `liquidation_fees` at creation, and the stored values — not the live listing — drive health factor, borrow limits, and liquidation payouts. However, the permissionless entrypoint `update_account_threshold(caller, has_risks, account_ids)` lets any authenticated address force-refresh those stamped terms on *any* account to the live spoke listing. When a listing edit makes terms worse for the position holder (lower liquidation threshold, higher liquidation bonus, lower liquidation fee), a third party can restamp a victim's position without their consent, materially worsening the terms under which their collateral will later be seized — the same class as the Loot.sol `updateVestingDuration` retroactive-slashing finding.

### Finding Description
The bug class is: a global parameter change is applied retroactively to existing user positions, so a user who entered under one set of terms is silently moved to worse terms.

In `contracts/controller/src/risk/params.rs`:

- `update_account_threshold` only requires `validation::require_authorized_caller(env, &caller)` — the caller's own auth, not the account owner's — and iterates arbitrary `account_ids` (`params.rs:124-144`). Any unprivileged address can target any account.
- For each supply position it calls `refresh_supply_risk_params`, which unconditionally writes the live `effective_config.loan_to_value` and, under `FullTuple` (`has_risks = true`), calls `apply_gated_liquidation_params` (`params.rs:25-40`).
- `favors_liquidator` treats a *lower* `liquidation_threshold`, a *higher* `liquidation_bonus`, or a *lower* `liquidation_fees` as adverse to the holder (`params.rs:96-100`).
- The only protection is the health-factor gate: adverse tuples apply to a debt-holding account only if HF under the new threshold is ≥ 1.05 (`THRESHOLD_UPDATE_MIN_HF_RAW`), and the account-level re-check at `params.rs:221-234` reverts the batch below that (`params.rs:68-119`). A debt-free account takes adverse values unconditionally.
- The same unguarded restamp also happens inside a victim's own later actions: every borrow and non-liquidation withdrawal refreshes stored LTV unconditionally via `restamp_listed_supply_ltv` / `merge_withdraw_leg` (`params.rs:44-64`), so a user's queued borrow/withdraw that lands after an `editAssetInSpoke` executes under worse terms than the ones shown when it was submitted — exactly the Loot.sol ordering scenario.

Unlike Loot.sol's fix (store the duration per-loot), the stamping itself already exists here; the defect is that adverse restamping is triggerable by unrelated third parties rather than being confined to the position owner's own risk decisions.

### Impact Explanation
A higher `liquidation_bonus` increases the collateral seized from the victim on every subsequent liquidation leg, and a lower `liquidation_threshold` makes the account liquidatable at a higher collateral price than it originally contracted for — both are direct, permanent losses of user funds paid to liquidators. The 1.05 HF gate prevents instant liquidation but does not prevent the loss: any later price drift pushes the account over the new, worse cliff, and liquidation paths never re-stamp back to the old vintage. Debt-free suppliers take adverse tuples with no gate at all.

### Likelihood Explanation
Requires a prior spoke listing edit (`edit_asset_in_spoke`) that makes a tuple adverse — a routine, timelocked governance operation whose scheduling is publicly visible via `OperationScheduled` events. Once scheduled/executed, any keeper or griefer can call `update_account_threshold(caller, true, [victim_ids])` the moment the victim's HF under the new LT is ≥ 1.05. No special access, capital, or timing race is needed. Comparable to the original report's low-to-medium likelihood, gated on how often adverse listing edits occur.

### Recommendation
Restrict adverse-tuple restamping so third parties cannot worsen another account's terms:
- In `sync_account_thresholds`, require `owner == caller` (or a delegate) whenever `favors_liquidator` is true for any position, or skip applying adverse tuples to accounts whose owner did not authorize the call; keep permissionless calls applying only non-adverse refreshes.
- Alternatively, store the tuple vintage per position (as the code already does) and only restamp adverse values on owner-initiated actions, keeping the HF≥1.05 gate as a second layer for `merge_supply_leg`/`merge_withdraw_leg`.

### Proof of Concept
1. Alice supplies collateral and borrows; her USDC supply position is stamped with `liquidation_threshold = 8000`, `liquidation_bonus = 400`, `liquidation_fees = 1000`.
2. Governance proposes and executes `AdminOperation::EditAssetInSpoke` lowering threshold to 6100, raising bonus, lowering fees (as exercised in `tests/test-harness/tests/controller/keeper.rs:268-299`, `test_update_account_threshold_propagates_adverse_tuple_to_healthy_account`).
3. Attacker Bob calls `update_account_threshold(caller = bob, has_risks = true, account_ids = [alice_id])`. `require_authorized_caller` only checks Bob's auth.
4. While Alice's HF under LT 6100 is ≥ 1.05, `apply_gated_liquidation_params` writes the adverse tuple; her stored threshold drops to 6100 and bonus rises.
5. On the next price move, Alice is liquidated earlier (at the lower threshold) and pays a larger bonus per seized leg than the terms she entered under — funds she cannot recover.