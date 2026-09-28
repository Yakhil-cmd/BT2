### Title
Stale cached liquidation threshold survives config tightening and cannot be refreshed on underwater accounts - (File: contracts/controller/src/risk/params.rs)

### Summary
Each account caches its spoke's LTV/liquidation-threshold snapshot. `update_account_threshold` is the only restamp path, and its risk refresh (`has_risks = true`) requires the account to finish with HF ≥ 1.05. After governance tightens a listing (lower LTV/threshold, or collateral uncollateralized via `edit_asset_in_spoke`), every account that is insolvent under the new parameters permanently retains the old, more lenient cached threshold — the exact analog of `dqi_priv` being freed but left dereferenceable: the stale value is still consulted, and the refresh path checks the wrong condition (post-refresh solvency rather than "was this config superseded").

### Finding Description
- `edit_asset_in_spoke` (`contracts/controller/src/config/asset.rs:29`) rewrites `SpokeAssetConfig` with new `loan_to_value`/`liquidation_threshold` without touching existing accounts — the old values stay live inside each account's stored risk snapshot.
- Per the protocol docs (`docs/reference/endpoints.md:39`), `update_account_threshold(caller, has_risks, account_ids)` is permissionless, but the risk-bearing refresh reverts unless the account ends at HF ≥ 1.05. ADR-0009 (`docs/explanation/decisions.md:81`) confirms "an account's stored risk values" are what get used until refreshed.
- Consequently, an account that is undercollateralized only under the *new* parameters can never be restamped: the refresh itself reverts, so health-factor and liquidation evaluation keep reading the dangling stale threshold (used in `risk/params.rs` / `risk/totals.rs` and the liquidation bonus curve in `positions/liquidation/curve.rs`).

### Impact Explanation
Positions that should be liquidatable under current risk parameters present a stale, higher threshold/LTV to the HF computation, so `liquidate` either rejects them or seizes less than intended. Interest keeps accruing on the un-liquidatable debt (`paused`-style DoS is not needed — no flag change required, just an ordinary timelocked `edit_asset_in_spoke`). The protocol accumulates bad debt and eventual insolvency; `clean_bad_debt` is the only exit and it socializes the loss into the supply index (INV-LIQ-04), harming all suppliers.

### Likelihood Explanation
Requires only a routine governance parameter change (e.g., lowering LTV/threshold on a volatile asset — a normal, expected operation) plus one account whose HF crosses 1.0 under the new config. The attacker needs no special privileges: they simply keep borrowing/maintaining a position whose safety relies on the stale snapshot, and any permissionless restamp attempt reverts.

### Recommendation
Recompute the account's risk parameters from the live `SpokeAssetConfig` at evaluation time, or make `update_account_threshold` always succeed for tightening refreshes regardless of the post-refresh HF (the HF ≥ 1.05 gate should apply only when the refresh would *relax* risk). Alternatively, gate liquidation/HF on `min(cached, live)` parameters.

### Proof of Concept
1. Alice supplies VOL collateral and borrows USD; listing LTV/threshold cached on her account at creation.
2. Governance timelocks and executes `edit_asset_in_spoke` lowering VOL's `ltv`/`threshold` (flags unchanged — ratchet permits this).
3. VOL price drops so Alice's HF is < 1 under the new threshold but ≥ 1 under her stale cached threshold.
4. Liquidator calls `liquidate(liquidator, alice_id, ...)` — it evaluates against the stale snapshot and fails admission.
5. Anyone calls `update_account_threshold(any, true, [alice_id])` — it recomputes HF under the new config, sees HF < 1.05, and reverts.
6. Alice's position is permanently unliquidatable; her debt accrues until `clean_bad_debt` socializes it into the supply index — confirmed insolvency.