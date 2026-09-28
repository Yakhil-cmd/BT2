### Title
Delisted collateral keeps its stamped risk weights forever and still underwrites new borrows — stale-state resolution divergence in `restamp_listed_supply_ltv` / `sync_account_thresholds` - (File: contracts/controller/src/risk/params.rs)

### Summary
Each supply position carries a stamped copy of `(loan_to_value, liquidation_threshold, liquidation_bonus, liquidation_fees)` copied from the spoke listing at creation. All refresh paths (`restamp_listed_supply_ltv` on borrow/withdraw gates, `refresh_supply_risk_params` on supply/withdraw legs, and `sync_account_thresholds` via `update_account_threshold`) resolve the *current* listing through `cache.cached_spoke_asset(account.spoke_id, &hub_asset)` and silently `continue` when the listing no longer exists. The result is two different resolutions of the same collateral state: a listed leg converges to the current config, while a leg whose `(spoke_id, hub_asset)` entry was removed keeps its old stamp indefinitely — yet still contributes its full stamped weight to `calculate_account_risk_totals` (LTV-weighted borrow capacity and threshold-weighted health factor) and remains seizable.

### Finding Description
- `restamp_listed_supply_ltv` (contracts/controller/src/risk/params.rs:44-64) iterates supply legs and skips any leg where `cached_spoke_asset` returns `None`, so a delisted asset's `loan_to_value` is never re-resolved.
- `sync_account_thresholds` (contracts/controller/src/risk/params.rs:182-185) applies the same `let Some(...) else { continue }` skip, so even the permissionless keeper path `update_account_threshold(caller, has_risks, account_ids)` cannot restamp or zero a delisted leg.
- `calculate_account_risk_totals` always uses the *stored* `loan_to_value`/`liquidation_threshold` (docs and `contracts/controller/src/risk/totals.rs`), so the delisted leg still supplies `ltv_collateral` for the borrow gate and `weighted_collateral` for HF.
- `enforce_spoke_asset_flags` (contracts/controller/src/positions/mod.rs:255-278) treats a missing listing as exitable/seizable, confirming the position remains live collateral; only new supply/borrow *of that asset* is blocked via `require_spoke_asset`.

So after governance removes a spoke listing — the typical response to a broken oracle feed, a compromised asset, or a deprecated spoke — every account holding that asset retains its pre-removal LTV/LT as valid collateral weight with no mechanism that ever converges it to zero. A holder can keep opening or increasing borrow positions in *listed* debt assets against collateral that governance has already voted out, until the stored stamp (not the live market) says otherwise.

### Impact Explanation
The stamped weights can be arbitrarily stale and arbitrarily generous relative to the reason for delisting. If the asset was delisted because its price feed is unreliable or the token became illiquid/worthless, an attacker holding a large position of it can still borrow listed assets (USDC, XLM, etc.) up to `min(stored_LTV, stored_LT)` of its stale stamped value — the borrow gate only restamps *listed* legs. The borrowed assets are real and withdrawable; the collateral backing them is precisely what governance intended to exclude. This produces under-collateralized debt and protocol insolvency once the bad collateral can't cover liquidations at its stamped threshold weight.

### Likelihood Explanation
Medium. The exploit needs a prior admin action (spoke asset removal or spoke deprecation that makes `get_spoke_asset` return `None`), but the triggering action — `borrow` — is fully permissionless, and the attacker needs only to hold the delisted asset, which is free to acquire after delisting crashes its price. Note `update_account_threshold` cannot remediate: it skips unlisted legs by the same `continue`, so there is no on-chain path to force the stale weight to zero.

### Recommendation
When `cached_spoke_asset` returns `None` for a held supply leg, resolve the leg's effective collateral weight to zero (or a conservative floor) in `restamp_listed_supply_ltv` and `sync_account_thresholds` — e.g., stamp `loan_to_value = 0` on delisted legs so the borrow gate and HF no longer credit them — while keeping the position exitable and seizable per `enforce_spoke_asset_flags`. Alternatively, make `calculate_account_risk_totals` treat unlisted legs as zero-weight collateral rather than trusting the frozen stamp.

### Proof of Concept
1. Alice supplies 100,000 units of token `X` on spoke 1 (listed, LTV 7500, LT 8000) and borrows some USDC. Her `AccountPosition` for `X` is stamped with `loan_to_value = 7500`, `liquidation_threshold = 8000` (`get_or_create_supply_position`).
2. Governance removes `X` from spoke 1 (`get_spoke_asset(1, X)` now returns `None` → `AssetNotInSpoke`).
3. Alice (or any holder of `X`) calls `borrow(alice, [(USDC, amount)])`. Inside the gate, `restamp_listed_supply_ltv` hits `cached_spoke_asset(1, X) == None` and `continue`s (params.rs:48-50); the leg keeps LTV 7500/LT 8000 and contributes `floor(value_floor × 7500/BPS)` to `ltv_collateral`.
4. The borrow succeeds up to the stale-weighted limit even though `X` is no longer a listed collateral. Calling `update_account_threshold(caller, true, [alice_id])` cannot fix it — `sync_account_thresholds` skips the leg identically (params.rs:183-185), so the stale stamp persists until `X` is relisted.