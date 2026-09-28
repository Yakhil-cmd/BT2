### Title
Unprivileged repay/supply front-runs state-gated `liquidate` and `clean_bad_debt`, flipping the victim's health-factor/dust predicate and forcing a revert - (File: contracts/controller/src/positions/debt.rs)

### Summary
The Symmio report's bug class is: a permissionless call mutates the very state predicate that a victim's pending transaction is gated on, so the victim's transaction reverts. XOXNO Lending exposes the same shape twice on its permissionless entrypoints:

1. `repay(caller, account_id, payments)` is callable by anyone against any account's debt — `process_repay` performs only `require_authorized_caller(caller)` and `caller.require_auth()`, with no owner/delegate check, and pulls the funds from the caller's own balance (`debt.rs:69-91`, `settle_repay` at `debt.rs:126-162`). `liquidate` is gated on the target's health factor being strictly below `WAD` (`build_liquidation_plan` raises `HealthFactorTooHigh`, controller error #101; `can_be_liquidated` is `health_factor < WAD` in `views.rs:47-49`). A watcher can front-run a pending `liquidate` with a dust `repay` that pushes HF from just below 1 WAD to ≥ 1 WAD, reverting the liquidator's transaction.
2. `supply` is permissionless into an existing supply slot of a foreign account, and `clean_bad_debt` is gated on `total_debt > total_collateral && total_collateral <= BAD_DEBT_USD_THRESHOLD` ($5 WAD) in `is_socializable_bad_debt` (`curve.rs:25-27`) enforced in `socialize_bad_debt` (`mod.rs:212-238`). A dust `supply` top-up that pushes residual collateral above $5 makes a pending `clean_bad_debt` revert with `CannotCleanBadDebt` (#114).

### Finding Description
- `process_repay` (`contracts/controller/src/positions/debt.rs:69`) authenticates only the caller and loads the target account borrow-side only (`get_account_borrow_only`), then `settle_repay` transfers the payer's own tokens to the pool and burns the victim's debt shares. The protocol explicitly documents this as permissionless ("Anyone may repay any account's debt", `scripts/permissionless_entrypoints.txt:70`).
- `process_liquidation` (`contracts/controller/src/positions/liquidation/mod.rs:36-58`) builds its plan via `plan::build_liquidation_plan`, which rejects with `HealthFactorTooHigh` when the account's HF is not below 1 WAD (pinned by `tests/test-harness/tests/controller/liquidation_and_borrow_exact_boundaries.rs:21-47`: HF exactly `WAD` reverts, `WAD - 3` succeeds). Because HF = weighted_collateral / debt, retiring even 1 base unit of debt near the boundary moves HF above the gate. The exact boundary test shows one minimal price/debt step is all that separates admitted from rejected.
- Symmetrically, `process_clean_bad_debt` → `clean_bad_debt_standalone` → `socialize_bad_debt(.., BadDebtGate::DustCapped)` (`mod.rs:195-243`) reverts with `CannotCleanBadDebt` unless collateral ≤ $5. A permissionless `supply` into the insolvent account's existing collateral slot (INV-AUTH-03 permits top-ups on existing slots only) lifts `total_collateral` above the threshold and DoS-es the pending cleanup.

### Impact Explanation
Temporary freezing of protocol-critical flows / delayed bad-debt processing. A liquidator's submitted `liquidate` reverts, so an account that should be closed stays open while its debt keeps accruing and prices can deteriorate further; the same trick keeps an insolvent account above the $5 dust gate, forcing cleanup onto the slower owner-gated `force_socialize_bad_debt` governance path. The attacker's cost is real but small: each grief donates the repaid/supplied dust to the victim/protocol, so sustained griefing is bounded by boundary proximity, not by the victim's balance — mirroring the report's medium-severity "keep flipping the gate so the protected action always reverts" pattern rather than a free permanent lock.

### Likelihood Explanation
Requires the victim account to sit within a dust repayment/top-up of the gate boundary (HF ≈ 1 WAD, or collateral ≈ $5). That is common exactly when liquidation/cleanup matters most — freshly underwater accounts and post-liquidation residual dust accounts. The attacker needs only a mempool watcher plus the permissionless `repay`/`supply` call; no privileges, no oracle manipulation, no leaked keys.

### Recommendation
There is no cheap in-protocol fix that preserves permissionless repay/supply, since the gates are economically correct. Mitigations:
- Document for liquidator bots that `liquidate` must be simulated and submitted with the minimal viable margin; treat `HealthFactorTooHigh`/`CannotCleanBadDebt` as expected front-run outcomes and resubmit rather than aborting.
- Where accepted, prefer private/orderflow-auction submission for liquidation bundles so the repay front-run cannot be inserted.
- Optionally, allow `liquidate` to proceed when the offered repayment itself would restore the gate condition (i.e., evaluate the gate on pre-repay state only — it already does — and have clients bundle "repay dust + liquidate" atomically so a front-run cannot strand the liquidator).

### Proof of Concept
Scenario A (liquidation block):
1. Alice supplies $10,000 USDC, borrows ETH; oracle move puts her HF at `WAD - 3` (liquidatable, per `liquidation_and_borrow_exact_boundaries.rs:39-47`).
2. Liquidator submits `liquidate(liquidator, alice_id, [(hub_eth, x)], SeizeMode::Transfer)`.
3. Attacker front-runs with `repay(attacker, alice_id, [(hub_eth, ε)])` where ε·price·index ≥ the few WAD units of debt keeping HF below 1. `process_repay` admits it (caller-auth only) and reduces Alice's scaled debt.
4. Liquidator's tx now computes HF ≥ `WAD` → `build_liquidation_plan` panics `HealthFactorTooHigh` (#101). Repeat per attempt while Alice hovers at the boundary.

Scenario B (cleanup block):
1. Post-liquidation residue: $4.99 collateral vs $22 debt — `is_socializable_bad_debt` admits cleanup (`curve.rs:25-27`).
2. Keeper submits `clean_bad_debt(caller, victim_id)`.
3. Attacker front-runs `supply(attacker, victim_id, [(hub_collateral, $0.02)])` into the existing slot (allowed by INV-AUTH-03), pushing collateral to $5.01.
4. `clean_bad_debt` reverts `CannotCleanBadDebt` (#114); debt keeps accruing until governance runs `force_socialize_bad_debt`.

Caveat: I verified the gates, permissionless auth classification, and revert errors from source and invariants docs, but did not read `plan.rs`'s exact `HealthFactorTooHigh` line or a test exercising the front-run sequence itself; the boundary revert behavior is pinned by the existing boundary tests cited above.