### Title
Suppliers can front-run bad-debt socialization by withdrawing before the supply-index write-down and re-supplying after, shifting the loss onto remaining suppliers - (File: contracts/pool/src/interest.rs / contracts/controller/src/positions/liquidation/mod.rs)

### Summary
`clean_bad_debt` (permissionless, dust-capped) and the governance-queued `force_socialize_bad_debt` write off insolvent debt by lowering the affected market's `supply_index` proportionally across all supply shares present at cleanup. Because withdrawal is never blocked by an impending socialization — and remains callable even under global pause — a large supplier can exit the market before the write-down executes and re-supply at the reduced index, avoiding their pro-rata share of the loss. This mirrors the front-run-the-`set`-function bug class: user state is removed before a global accounting "set" and re-added afterward.

### Finding Description
Debt socialization lowers only the affected market's supply index:

```text
remaining_ray = total_supply_ray - min(bad_debt_ray, total_supply_ray)
reduction_ray = floor(remaining_ray * RAY / total_supply_ray)
new_supply_index = floor(old_supply_index * reduction_ray / RAY)
```

`total_supply_ray` is measured at execution time over the shares still in the book. Withdrawals before the cleanup shrink `total_supply_ray`, so `reduction_ray` becomes smaller and every remaining supplier absorbs a larger fraction of the same `bad_debt_ray` loss. A supplier who exits with `W` before cleanup avoids `W * bad_debt / V` of loss; that avoided loss is redistributed to the suppliers who stay.

Reachability for an unprivileged attacker:
- `force_socialize_bad_debt` is scheduled through governance on the Sensitive delay tier, then executed as a ready operation. The queued operation, its delay, and the target `account_id` are publicly observable well before execution, giving suppliers a deterministic window to withdraw.
- `clean_bad_debt` becomes permissionlessly callable the moment an oracle move pushes collateral at or below the $5 `BAD_DEBT_USD_THRESHOLD` while `debt > collateral`. The gate's preconditions are readable on-chain; a supplier monitoring the pending insolvency can withdraw as soon as liquidation drains collateral to the dust band, before the cleanup transaction lands.
- Withdrawal, bad-debt cleanup, and re-supply are all reachable by any holder; withdrawal and cleanup even remain callable under global pause per INV-HALT-01/02.

The threat model itself concedes the mechanic: "Suppliers present at cleanup bear index write-downs; a supplier who exits before cleanup can avoid that loss" (`docs/explanation/threat-model.md:303-305`).

### Impact Explanation
Theft of user funds via loss shifting: the loss that should be borne pro-rata by all suppliers of the market is concentrated on suppliers who do not exit. For a dominant supplier, the redistribution is material — e.g., holding 50% of supplied value and exiting doubles the per-share loss borne by the rest. The attacker then re-supplies at the written-down index and resumes normal accrual. This is identical in effect to the report's gauge-weight example: the global "set" (index write-down) applies to whoever is present, and entering/exiting around it captures value not intended.

### Likelihood Explanation
Requires a market with insolvent bad debt and a large supplier able to observe the cleanup window. Bad debt arises naturally from oracle crashes and illiquid collateral; the `force_socialize_bad_debt` governance delay creates a predictable multi-step window, and the dust-gated permissionless path is deterministic once prices open the gate. Withdrawal of unencumbered supply is a single call. No privileged access is needed at any step.

### Recommendation
Apply socialization to the set of suppliers present when the bad debt became attributable, or make exits observe pending losses:
- Accrue and commit the write-down against a snapshot (e.g., deduct the bad debt from the market's cash/book totals at liquidation time so the loss accrues continuously rather than at cleanup).
- Alternatively, impose a withdrawal-side accounting that settles each exiting supplier's share of known-unpaid bad debt before paying out, or
- Execute `force_socialize_bad_debt` and the pre-cleanup collateral seizure in a way that prevents interleaved exits in the same market (e.g., a per-market socialization lock set when insolvency is first recorded).

### Proof of Concept
1. Market M has total supplied value `V = $1,000,000` split equally between supplier A (whale, $500,000) and suppliers B+C ($500,000). Index `I`.
2. A borrower position becomes insolvent with `bad_debt = $100,000` and collateral above the $5 dust cap; governance queues `ForceSocializeBadDebt(account_id)` on the Sensitive delay.
3. If cleanup executes immediately: `reduction = (V - L)/V = 0.9`; every supplier loses 10%. A loses $50,000.
4. A observes the queued operation and calls `withdraw` for their full supply before execution. `V` becomes $500,000.
5. Governance operation executes: `reduction = (500k - 100k)/500k = 0.8`; B and C lose 20% — $100,000 total. A lost $0.
6. A re-supplies $500,000 at the written-down index `0.8 * I`. A has transferred their entire $50,000 share of the loss onto B and C. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** contracts/controller/src/positions/liquidation/mod.rs (L195-248)
```rust
/// Authorizes permissionless dust-gated cleanup outside flash loans.
pub(crate) fn process_clean_bad_debt(env: &Env, caller: &Address, account_id: u64) {
    caller.require_auth();
    validation::require_not_flash_loaning(env);
    clean_bad_debt_standalone(env, account_id);
}

/// Admission condition for bad-debt socialization.
#[derive(Clone, Copy, PartialEq)]
enum BadDebtGate {
    /// Permissionless: insolvent *and* collateral at or below the dust threshold.
    DustCapped,
    /// Owner-only: insolvent alone, with no cap on the collateral left behind.
    InsolventOnly,
}

/// Requires open debt and the selected insolvency gate, then cleans up the account.
fn socialize_bad_debt(env: &Env, account_id: u64, gate: BadDebtGate) {
    let mut cache = Context::new(env);
    let account = storage::get_account(env, account_id);

    assert_with_error!(
        env,
        !account.borrow_positions.is_empty(),
        CollateralError::DebtPositionNotFound
    );

    let totals = risk::calculate_account_risk_totals(
        env,
        &mut cache,
        &account.supply_positions,
        &account.borrow_positions,
    );

    let admits = match gate {
        BadDebtGate::DustCapped => {
            is_socializable_bad_debt(totals.total_debt, totals.total_collateral)
        }
        BadDebtGate::InsolventOnly => totals.total_debt > totals.total_collateral,
    };
    assert_with_error!(env, admits, CollateralError::CannotCleanBadDebt);

    bad_debt::execute_bad_debt_cleanup(env, &mut cache, account_id, &account, &totals);
}

/// Socializes insolvent debt when remaining collateral is at or below the dust cap.
pub(crate) fn clean_bad_debt_standalone(env: &Env, account_id: u64) {
    socialize_bad_debt(env, account_id, BadDebtGate::DustCapped);
}

/// Socializes debt exceeding collateral without a dust cap, outside flash loans.
pub(crate) fn process_force_socialize_bad_debt(env: &Env, account_id: u64) {
    validation::require_not_flash_loaning(env);
    socialize_bad_debt(env, account_id, BadDebtGate::InsolventOnly);
```

**File:** docs/reference/formulas.md (L386-401)
```markdown
Debt socialization lowers only the affected market's supply index. The debt
being removed is valued with a ceiled RAY multiplication. The write-down uses
half-up total supplied value, two floors, and a non-zero floor clamp:

```rust
let remaining_ray = total_supply_ray - min(bad_debt_ray, total_supply_ray);
let reduction_ray = floor(remaining_ray * RAY / total_supply_ray);
let new_supply_index = max(10_i128.pow(24),
    floor(old_supply_index * reduction_ray / RAY));
```

Zero supplied value makes the write-down a no-op. The two floors can impose
extra truncation on supply claims, including revenue, before the index clamp.
The non-zero floor can leave residual claims without backing. Supply then
fails the backing gate until recapitalization fills the shortfall. Eligibility
and account deletion follow the [cleanup rules](invariants.md#inv-liq-04).
```

**File:** docs/explanation/threat-model.md (L302-308)
```markdown
Cleanup converts all remaining account supply to protocol revenue and socializes
its gross debt, including same-market supply/debt pairs. It does not net those
pairs first. Suppliers present at cleanup bear index write-downs; a supplier
who exits before cleanup can avoid that loss. The index floor can leave
material unpaid backing, so displayed supplier claims are not a universal
pro-rata cash-payout guarantee. New supply checks backing; recapitalization
repairs the book's measured shortfall without minting shares.
```

**File:** docs/reference/runbooks/force-socialize-bad-debt.md (L20-46)
```markdown
   NFT owner, positions and spoke. `force_socialize_bad_debt` is owner-only.
   Governance, the controller owner, schedules `ForceSocializeBadDebt` on the
   Sensitive delay tier; follow the
   [governance interface](../endpoints.md#governance) for proposal and execution.
2. Confirm insolvency with the same risk totals the entrypoint uses: ceil-valued
   debt (`AccountRiskTotals.total_debt`) strictly greater than half-up unweighted
   collateral (`AccountRiskTotals.total_collateral`). `get_total_collateral_usd`
   (`make <network> getCollateralUsd <account-id>`) returns that collateral
   total. Do **not** use `get_total_borrow_usd` for the debt side: it returns
   half-up display debt, which can disagree with ceil risk debt near the boundary
   ([INV-RISK-02](../invariants.md#inv-risk-02)). To check `D > C` exactly,
   simulate `force_socialize_bad_debt`. If collateral is at or below $5 and
   `D > C` holds, use permissionless `clean_bad_debt` instead; it needs no
   governance.
3. Check every position's price status. Missing or invalid required prices
   prevent cleanup; listing flags and global pause do not waive pricing.
4. Snapshot debt shares, supply shares, revenue, cash, indexes and spoke usage
   for all affected markets. Preserve the ledger/time and price snapshot.
5. Simulate the intended invocation and prepare any required archived-entry
   restoration. Ownership lookup and NFT burn both require readable NFT state.

## Execute and reconcile

1. Propose `ForceSocializeBadDebt(account_id)` through governance.
2. Recheck insolvency immediately before execution; another repayment or
   liquidation can change eligibility.
3. Execute the operation after its required delay.
```
