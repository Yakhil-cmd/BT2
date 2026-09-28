### Title
Permissionless `update_account_threshold` force-applies tightened LTV to foreign accounts, freezing their withdrawals - (File: contracts/controller/src/risk/params.rs)

### Summary
`update_account_threshold` is permissionless: any authenticated caller can restamp the cached `loan_to_value` on every supply position of arbitrary foreign `account_ids` to the currently listed spoke config (`has_risks = false`, `RiskRefreshScope::LtvOnly`). After governance tightens a spoke asset's LTV, an attacker can immediately restamp a victim's positions, driving their LTV-weighted collateral below their debt. Because `withdraw`, `borrow`, and all strategy entrypoints require LTV-weighted collateral to cover debt, while the health factor (liquidation threshold, not LTV) may stay ≥ 1, the victim's funds become unwithdrawable and unliquidatable — a freeze reachable by a single unprivileged address.

### Finding Description
The bug class of the external report is an unauthenticated endpoint that mutates a critical per-entity status (a node's voter status) and thereby degrades the system. The analog here is the unauthenticated restamp of a foreign account's cached risk status.

- `update_account_threshold(env, caller, has_risks, account_ids)` only calls `require_authorized_caller(env, &caller)` — the caller merely signs for themselves; there is no per-account ownership check (`contracts/controller/src/risk/params.rs:124-144`). The declared exception list confirms it is permissionless keeper maintenance (`scripts/permissionless_entrypoints.txt:76`).
- With `has_risks = false`, `sync_account_thresholds` → `refresh_supply_risk_params` unconditionally writes `position.loan_to_value = effective_config.loan_to_value` and persists via `storage::set_supply_positions` (`params.rs:35`, `params.rs:217-219`). The `favors_liquidator` / `clears_min_hf` gate only applies under `FullTuple`; LTV writes are ungated (`params.rs:36-38`, `params.rs:76-93`).
- Stored per-position `loan_to_value` is what risk totals read (`risk/totals.rs`), and the risk-check rules require LTV-weighted collateral to cover debt after `withdraw`, `borrow`, and the six strategy calls (`docs/reference/endpoints.md:53-55`).
- The health factor that gates `liquidate` is computed from `liquidation_threshold`, which `LtvOnly` does not touch. So a victim whose LTV is force-lowered cannot withdraw (`LtvCollateralTooLow`-style revert) yet still cannot be liquidated — the account is stuck until they repay debt out of pocket or governance relaxes the parameter.

The justification in the permissionless inventory only argues the endpoint "cannot be used to push an account into liquidation"; it does not bound the withdrawal-blocking effect of an unrequested LTV downgrade.

### Impact Explanation
Temporary freezing of user funds, triggered entirely by an unprivileged third party. Once governance tightens a spoke asset's LTV (a routine, timelocked operation that does happen as risk parameters evolve), any address can walk the set of accounts supplying that asset and restamp them. Accounts whose new LTV-weighted collateral falls below outstanding debt lose the ability to `withdraw` collateral, `borrow`, or run collateral strategies. Since `liquidate` keys off liquidation threshold (untouched by `LtvOnly`), there is no market mechanism to unlock the position; the only exits are repaying debt or waiting for a governance parameter change. This is a conditional, griefing-class freeze rather than permanent loss, which caps the severity at Medium.

### Likelihood Explanation
Requires a governance LTV tightening to create the wedge, then a single permissionless call per victim — cheap and always executable while unpaused. The attacker gains no direct profit, so motivation is griefing/extortion rather than theft, which lowers practical likelihood. Guards that do exist (flash-loan rejection, HF floor) only protect the `FullTuple` path and liquidation, not the LTV downgrade itself.

### Recommendation
Gate `LtvOnly` restamps so a third party can only restamp an account when the change is non-worsening for that account, mirroring the `favors_liquidator` pattern: skip positions where `effective_config.loan_to_value < position.loan_to_value` unless the caller is the account owner/delegate, or apply the LTV downgrade lazily at the account owner's next interaction instead of letting strangers force it. Alternatively, restrict `update_account_threshold` callers for LTV-lowering restamps to the account owner, delegate, or a keeper role.

### Proof of Concept
1. Alice supplies 10,000 USDC in spoke 1 (listed LTV 9000 BPS) and borrows 8,000 USDC-equivalent; LTV-weighted collateral 9,000 ≥ debt. HF ≥ 1.
2. Governance timelocks and executes `edit_asset_in_spoke` lowering USDC's LTV in spoke 1 to 7000 BPS (a tightening, permitted direction).
3. Attacker Bob calls `controller.update_account_threshold(bob, false, [alice_id])`. `sync_account_thresholds` rewrites Alice's stored `loan_to_value` to 7000 BPS with no health-factor gate (`params.rs:35`, `params.rs:191-205`).
4. Alice calls `withdraw(alice, alice_id, [(usdc, 1)], None)`: post-withdraw LTV-weighted collateral is 7,000 < 8,000 debt → reverts. `borrow`, `multiply`, `swap_collateral`, and `repay_debt_with_collateral` similarly revert.
5. `liquidate` still reverts: Alice's health factor uses `liquidation_threshold` (unchanged, e.g., 9300 BPS → HF ≈ 1.16 > 1). Her collateral is frozen until she repays debt from external funds or governance raises the LTV — all caused by Bob's single unprivileged call.

Caveat: this assumes withdrawal solvency is evaluated against the stored per-position `loan_to_value`, as documented in `docs/reference/endpoints.md` ("LTV-weighted collateral to cover debt") and as read by `risk/totals.rs`; the exception list itself acknowledges the endpoint only via the liquidation angle, leaving the withdrawal-freeze path unaddressed.