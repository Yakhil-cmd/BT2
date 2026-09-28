### Title
Unprivileged dust-donation griefing permanently gates `clean_bad_debt` behind the owner-only force path - (File: contracts/controller/src/positions/liquidation/mod.rs)

### Summary
The permissionless bad-debt cleanup path admits an insolvent account only while its total collateral is at or below a dust cap. Because `supply` lets any third party top up a position the target account already holds, anyone can donate a small amount of an asset the insolvent account still carries, push `total_collateral` above the dust gate, and make every `clean_bad_debt` call revert with `CannotCleanBadDebt`. The only remaining socialization path is owner-gated, and the attacker can re-grief after each forced cleanup attempt, so loss socialization — and the supply-index write-down that frees suppliers' realizable balances — is held hostage for dust-threshold cost per round.

### Finding Description
`clean_bad_debt` is the permissionless entrypoint: `process_clean_bad_debt` only requires `caller.require_auth()` and the flash guard, then runs `socialize_bad_debt(env, account_id, BadDebtGate::DustCapped)` [1](#0-0) . The gate computes `is_socializable_bad_debt(totals.total_debt, totals.total_collateral)` and reverts with `CollateralError::CannotCleanBadDebt` when the account's remaining collateral exceeds the dust cap [2](#0-1) .

`controller::supply` is deliberately open to third parties for slots the account already holds: "Anyone may top up an account they do not own, but only for hub assets it already holds a supply position in" [3](#0-2) . An insolvent account awaiting cleanup by definition still has dust collateral, i.e., at least one existing supply position, so it is always a valid top-up target.

For an insolvent account the liquidation quote is capped at `floor(C / (1 + base_bonus))`, so no liquidator can repay the whole debt or drain the collateral leg — liquidation cannot substitute for cleanup, and the leftover dust position persists [4](#0-3) .

The attacker's transaction is a single `supply(account_id, hub_id, asset, amount)` on an asset the insolvent account already supplies, where `amount` is just enough to lift `total_collateral` over the dust threshold. Thereafter:

- every `clean_bad_debt(account_id)` reverts at the `DustCapped` gate;
- the fallback `process_force_socialize_bad_debt` is owner-gated (`BadDebtGate::InsolventOnly`) [5](#0-4) ;
- after each forced cleanup is scheduled, the attacker can donate again before execution, re-blocking the permissionless path at dust-threshold cost.

### Impact Explanation
Analog of the report class (an attacker-induced crash/hang that denies a core operation): an unprivileged address can indefinitely stall the protocol's loss-socialization operation. While bad debt sits unsocialized, the supply index is never written down, so the book keeps showing unbacked supply; suppliers bear delayed realization of losses and face impaired pro-rata cash payouts (documented consequence of delayed/blocked cleanup and the index floor) [4](#0-3) . This is temporary freezing of supplier funds plus persistent protocol insolvency accounting, forced into the privileged `force_socialize_bad_debt` path on every occurrence. Severity: Medium — the damage is a deny-of-service on cleanup with bounded (dust-threshold-scale) attacker cost, mitigated by an existing governed fallback but never resolved by it since re-griefing is cheap.

### Likelihood Explanation
Triggering requires only: (1) an insolvent account exists — routine under volatile prices or during price-outage windows; (2) one listed asset the account already supplies, which is guaranteed by the dust collateral; (3) a dust-threshold-sized token donation. No privileged role, no oracle manipulation, no leaked keys, and no cooperation are needed — just the intended third-party `supply` semantics of INV-AUTH-03 [3](#0-2) . The attacker even recovers value partially, since donated supply is converted to protocol revenue at cleanup, but only after delaying each cleanup round.

### Recommendation
Exclude third-party (non-owner, non-delegate) top-ups from counting toward the dust gate, or measure the cleanup gate on the collateral that existed before the current transaction's donations — e.g., snapshot `total_collateral` used by `is_socializable_bad_debt` against pre-donation positions, or record a per-account "foreign supply" amount and subtract it in `socialize_bad_debt`. A cheaper alternative: permit only the account owner/delegate (or the flash-guard-free permissionless cleanup path) to top up a slot when the account is insolvent (`total_debt > total_collateral`), since supplying to an insolvent foreign account has no legitimate purpose.

### Proof of Concept
1. Market state: ALICE's account is insolvent — `total_debt > total_collateral` — with residual XLM supply dust worth just under the dust threshold (e.g., post-liquidation remainder per the residual-leg shape exercised in `audit_liquidate_dust_fee_dos.rs`).
2. CAROL (attacker) calls `controller::supply` with `account_id = ALICE`, asset = XLM (a slot ALICE already holds — allowed under INV-AUTH-03), amount = dust threshold + ε worth of XLM. `caller.require_auth()` passes; the account check permits existing-slot top-ups.
3. KEEPER calls `controller::clean_bad_debt(account_id = ALICE)`. `socialize_bad_debt` computes `is_socializable_bad_debt(total_debt, total_collateral)`; `total_collateral` now exceeds the dust cap, so the assertion fails and the call reverts with `CollateralError::CannotCleanBadDebt` [2](#0-1) .
4. Liquidators cannot substitute: the insolvent quote `floor(C / (1 + base))` is bounded by collateral, so `liquidate` cannot retire the full debt or empty the supply leg.
5. Result: the account's bad debt remains on the books and the supply index is never written down until the owner runs `force_socialize_bad_debt`; CAROL repeats step 2 each round to re-block the permissionless path at ~dust-threshold cost.

### Citations

**File:** contracts/controller/src/positions/liquidation/mod.rs (L196-200)
```rust
pub(crate) fn process_clean_bad_debt(env: &Env, caller: &Address, account_id: u64) {
    caller.require_auth();
    validation::require_not_flash_loaning(env);
    clean_bad_debt_standalone(env, account_id);
}
```

**File:** contracts/controller/src/positions/liquidation/mod.rs (L229-235)
```rust
    let admits = match gate {
        BadDebtGate::DustCapped => {
            is_socializable_bad_debt(totals.total_debt, totals.total_collateral)
        }
        BadDebtGate::InsolventOnly => totals.total_debt > totals.total_collateral,
    };
    assert_with_error!(env, admits, CollateralError::CannotCleanBadDebt);
```

**File:** contracts/controller/src/positions/liquidation/mod.rs (L245-249)
```rust
/// Socializes debt exceeding collateral without a dust cap, outside flash loans.
pub(crate) fn process_force_socialize_bad_debt(env: &Env, account_id: u64) {
    validation::require_not_flash_loaning(env);
    socialize_bad_debt(env, account_id, BadDebtGate::InsolventOnly);
}
```

**File:** scripts/permissionless_entrypoints.txt (L69-69)
```text
controller::supply | caller-auth | INV-AUTH-03, INV-ACCT-03 | Anyone may top up an account they do not own, but only for hub assets it already holds a supply position in; a caller that is neither the owner nor an active delegate cannot open a new asset slot, and account_id 0 creates an account owned by the caller.
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
