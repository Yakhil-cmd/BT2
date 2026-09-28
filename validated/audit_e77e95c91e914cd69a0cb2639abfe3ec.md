### Title
Liquidations execute against stale cached liquidation thresholds until someone calls `update_account_threshold` - (File: contracts/controller/src/risk/params.rs)

### Summary
Each supply position stores a snapshotted `(liquidation_threshold, liquidation_bonus, liquidation_fees)` tuple that is only refreshed when the permissionless `update_account_threshold` entrypoint is invoked. After governance raises a market's liquidation threshold (making existing borrowers safer), positions keep the old, stricter threshold, so an account that is healthy under current config remains liquidatable until an arbitrary third party pokes the restamp function — the same lazy state-transition class as the Carapace finding.

### Finding Description
`SpokeAssetConfig` holds the live market risk parameters (`liquidation_threshold`, `liquidation_bonus`, `liquidation_fees`), written by `edit_asset_in_spoke` in `contracts/controller/src/config/asset.rs:29`. However, liquidation math does not read the live config; it reads the per-position tuple snapshotted in `AccountPosition`, which is only overwritten inside `refresh_supply_risk_params` / `apply_gated_liquidation_params` (`contracts/controller/src/risk/params.rs:68-93`).

That restamp happens exclusively inside `sync_account_thresholds`, reached only through `update_account_threshold(caller, has_risks, account_ids)` (`params.rs:124-144`). Nothing in the borrow, withdraw, or liquidate flows applies the new liquidation tuple first. So between `edit_asset_in_spoke` committing new parameters and the first `update_account_threshold` call covering a given account, that account is evaluated under superseded risk parameters.

Note the asymmetry in `apply_gated_liquidation_params`: changes that favor the liquidator (lower threshold, higher bonus, lower fees) are gated behind a hypothetical HF ≥ 1.05 check (`params.rs:76-88`), so they may be deferred by design. Changes favoring the borrower (higher `liquidation_threshold`) fail `favors_liquidator` (`params.rs:96-100`) and are applied unconditionally — but still only on the next `update_account_threshold` call. The window is deterministic and permissionless to close, yet nothing forces it closed.

### Impact Explanation
A liquidator can seize a borrower's collateral, collecting `liquidation_bonus` and `liquidation_fees`, against an account whose health factor is ≥ 1 under the market's current stored `SpokeAssetConfig`. The borrower suffers an unambiguous loss of funds (collateral seized plus liquidation penalty) purely because the restamp entrypoint had not been called. This is theft of user funds: the protocol's own committed configuration says the account is safe, but the stale snapshot makes it liquidatable.

### Likelihood Explanation
- Triggering requires a governance `edit_asset_in_spoke` that raises a liquidation threshold — a routine, legitimate risk-parameter tuning, not an adversarial precondition.
- The vulnerable window lasts until anyone calls `update_account_threshold` for the affected account. The function is permissionless (`require_authorized_caller` plus auth, `params.rs:130`), but nothing incentivizes or automates the call, and it is not invoked implicitly by `liquidate`, `borrow`, or `withdraw`.
- A liquidator simply calls `liquidate` during the window; the plan is computed against `position.liquidation_threshold`, not `spoke_config.liquidation_threshold`. No special timing, capital, or privilege is needed — any liquidatable-under-stale-params account is a valid target.

### Recommendation
Restamp the account's liquidation tuple at the start of `liquidate` (reuse `refresh_supply_risk_params` with `RiskRefreshScope::FullTuple` semantics before computing the liquidation plan), so risk evaluation always uses parameters no older than the transaction itself. Alternatively, document and enforce a protocol-level keeper obligation — but on-chain enforcement inside the liquidation path is the only fix that removes the window entirely.

### Proof of Concept
1. Market M has `liquidation_threshold = 80%`. Borrower B supplies collateral in M and borrows such that HF ≈ 1.10 under the 80% threshold; the position snapshot stores 80%.
2. Governance calls `edit_asset_in_spoke`, raising M's threshold to 90%. Under the live config, B's HF is now ≈ 1.24 — comfortably safe.
3. No one calls `update_account_threshold` for B's account.
4. Collateral price dips slightly. Under 90% threshold B's HF is ≈ 1.02 — still safe; under the stale 80% snapshot it drops below 1.0.
5. Liquidator calls `liquidate` on B. The plan uses `position.liquidation_threshold = 80%`, computes HF < 1, and seizes collateral plus `liquidation_bonus` and `liquidation_fees` — against an account the protocol's own current parameters classify as healthy.
6. Had anyone called `update_account_threshold(caller, true, [B])` first, `apply_gated_liquidation_params` would have written 90% into the position (it does not favor the liquidator, so the HF ≥ 1.05 gate at `params.rs:78-88` is skipped) and the liquidation would have reverted.