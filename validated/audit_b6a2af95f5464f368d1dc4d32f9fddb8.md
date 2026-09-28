### Title
Unprivileged caller can force-restamp a lower LTV snapshot on any account, freezing that account's withdraw/borrow solvency gate - (File: contracts/controller/src/risk/params.rs)

### Summary
`update_account_threshold` is permissionless and, when called with `has_risks = false`, unconditionally overwrites every listed supply position's cached `loan_to_value` with the current listing value — with no health-factor gate, no owner check, and no `favors_liquidator` analysis. Because `require_post_pool_risk_gates` enforces `ltv_collateral >= total_debt` on `withdraw` and `borrow`, an attacker can apply a governance-reduced LTV to a victim account and immediately freeze its withdrawals and borrows. The same restamp is also reachable through a dust `supply` top-up of an existing leg, which calls the same refresh logic.

### Finding Description
- `update_account_threshold` takes `caller`, `has_risks`, and `account_ids`, calls only `require_authorized_caller` (bare `caller.require_auth()` + flash guard), then iterates `sync_account_thresholds` over arbitrary victim ids (`contracts/controller/src/lib.rs:386`, `risk/params.rs:124-144`).
- `refresh_supply_risk_params` writes `position.loan_to_value = effective_config.loan_to_value` unconditionally for `LtvOnly` scope; the `clears_min_hf` / `favors_liquidator` gate at `params.rs:68-93` only applies to `FullTuple` (liquidation threshold/bonus/fee), never to LTV (`params.rs:35-39`).
- `require_post_pool_risk_gates` computes `totals.ltv_collateral >= totals.total_debt` and reverts with `InsufficientCollateral` on `withdraw` and `borrow` (`risk/validation.rs:34-45`). The stored per-position LTV is exactly what was restamped.
- The harness test `poc_third_party_top_up_force_restamps_ltv` (`tests/test-harness/tests/controller/security_audit.rs:507-532`) proves the primitive end-to-end via `supply`: a 1-unit third-party top-up force-restamps LTV 8000→5000 and the victim's next borrow reverts `INSUFFICIENT_COLLATERAL`. `update_account_threshold(false, …)` reaches the identical write path with zero cost to the attacker.
- The declared justification in `scripts/permissionless_entrypoints.txt:76` claims LTV "the health factor does not read" — true for the HF leg, but false for the LTV solvency leg, so the permissionless surface silently enables unauthorized alteration of another account's solvency boundary.

### Impact Explanation
An attacker can force any borrower account into a state where `withdraw` and `borrow` revert. This is a temporary freezing of user funds: the victim's collateral cannot be moved until they repay enough debt to satisfy the new (lower) LTV or governance restores the parameter. It also enables griefing that blocks `multiply`/`swap_collateral`/other strategies that share the gate, and can be applied to many accounts in one batch. No funds are stolen and HF/liquidation terms are untouched, which caps the impact at temporary freezing — Medium severity.

### Likelihood Explanation
The trigger requires a governance LTV reduction on a listed spoke asset — a routine risk-management action — after which any unprivileged address can apply it to any victim for free, in any size batch. Repaying or waiting for an LTV raise unfreezes the victim, but the victim has no way to opt out or prevent the restamp; the account owner is never consulted. Exploitation needs no capital (the `update_account_threshold` path) or dust-level capital (the `supply` top-up path).

### Recommendation
Require the account owner or an active delegate — or at minimum apply the same HF gate used for `FullTuple` — before writing a *lower* `loan_to_value` into another account's stored position. Concretely, in `refresh_supply_risk_params`/`sync_account_thresholds`, skip (or hold) LTV decreases for non-owner callers when the hypothetical LTV would drop `ltv_collateral` below `total_debt`, mirroring `clears_min_hf`; always allow LTV *increases*, which only help the account. Apply the same owner/delegate or HF-gated rule to the third-party `supply` top-up path so a dust deposit cannot be used as the restamp trigger.

### Proof of Concept
1. Alice calls `supply(alice, 0, spoke, [(USDC, 10_000)])` then `borrow(alice, id, [(ETH, ~3.5)])` at LTV 8000, leaving `ltv_collateral ≈ total_debt`.
2. Governance lowers USDC `loan_to_value` to 5000 via `edit_asset_in_spoke` (existing accounts keep the cached 8000 stamp).
3. Attacker Bob calls `update_account_threshold(bob, false, [alice_id])` — no owner check — which restamps Alice's stored LTV to 5000 (`params.rs:35`).
4. Any `withdraw(alice, id, …)` or `borrow` now reverts with `InsufficientCollateral` (`validation.rs:43`), freezing Alice's collateral.
   Equivalent trigger without the keeper entrypoint: `supply(bob, alice_id, spoke, [(USDC, 1)])` — the harness test `poc_third_party_top_up_force_restamps_ltv` already demonstrates the borrow block under this path.