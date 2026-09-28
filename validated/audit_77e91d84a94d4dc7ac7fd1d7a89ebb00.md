### Title
Delisted collateral keeps its stamped LTV/LT forever — a "ghost" supply position that no refresh path can revoke - (File: contracts/controller/src/risk/params.rs)

### Summary
CVE-2022-30698 is a "ghost domain" bug: cached delegation data keeps a revoked domain resolvable because the resolver never validates cached child records against the revoked parent. The analog in XOXNO Lending is the per-position stamped risk tuple (`loan_to_value`, `liquidation_threshold`, `liquidation_bonus`, `liquidation_fees`) on supply legs. Once governance removes a spoke listing (`remove_spoke_asset` deletes `ControllerKey::SpokeAsset`), every refresh path skips the now-unlisted leg, so the revoked collateral keeps its pre-revocation LTV and liquidation threshold in every health-factor and borrow-power calculation, permanently.

### Finding Description
Each `AccountPositionRaw` stores its own LTV/LT/bonus/fee snapshot, and risk totals use the stored values, not the live listing: `calculate_account_risk_totals_body` iterates **all** supply positions and weights them by `position.loan_to_value` / `position.liquidation_threshold` with no check that the asset is still listed in the account's spoke (contracts/controller/src/risk/totals.rs:171-198).

All revocation-side refresh paths fail-open on a missing listing:

- `restamp_listed_supply_ltv` — used by `enforce_post_pool_solvency` before every borrow/withdraw/strategy gate — does `let Some(listed) = cache.cached_spoke_asset(...) else { continue }`, skipping unlisted legs (contracts/controller/src/risk/params.rs:44-50, contracts/controller/src/positions/mod.rs:83-91).
- `sync_account_thresholds` (the permissionless keeper entrypoint `update_account_threshold`) has the identical `let Some(spoke_config) ... else { continue }` skip (contracts/controller/src/risk/params.rs:182-185).
- The supply/withdraw merge paths only refresh legs that pass listing checks.
- `enforce_spoke_asset_flags` intentionally tolerates missing listings on exit/seizure ("Missing listings remain exitable and seizable so delisting cannot strand positions", contracts/controller/src/positions/mod.rs:255-277) — but nothing ever zeroes or downgrades the stored risk weights of the ghost leg.

`remove_spoke_asset` deletes the `SpokeAsset` row outright (contracts/controller/src/storage/spoke.rs:71-75), after which `get_spoke_asset`/`cached_spoke_asset` return `None` forever. Like Unbound's ever-refreshing child delegation, the stale stamped tuple is self-sustaining: no call — by the owner, a keeper, or governance — can restamp it to zero, because every writer requires the listing to exist.

### Impact Explanation
After governance delists an asset (the standard response to a dead/manipulated oracle or a compromised token), every account holding that supply leg keeps full borrowing power and liquidation-threshold credit at the old parameters. An attacker holding the revoked collateral can:

- Keep borrowing other assets against collateral the protocol intended to revoke, up to the stale `min(LTV, LT)` weight — `enforce_post_pool_solvency` restamps only *listed* legs, so the ghost leg's stored LTV is used verbatim.
- Resist liquidation: HF keeps the stale `liquidation_threshold`, so the account stays healthier than intended (mirroring the pinned `poc_stale_lt_stamp_blocks_liquidation_after_threshold_cut` behavior, except here the staleness is permanent rather than waiting on a keeper).
- Retain a stale high liquidation bonus when liquidated.

There is no recovery path: `update_account_threshold` skips the leg, and re-listing would apply current params only to legs touched afterward. Result: borrowing against revoked collateral → protocol insolvency/bad debt. Medium severity consistent with the source report: it requires a governance delisting event while positions exist, but is then reachable by any unprivileged account holder through ordinary `borrow`/`withdraw` calls.

### Likelihood Explanation
Delisting a deteriorating asset is a routine risk-off action. The bug requires no timing, flash loan, or price manipulation — the mere existence of a supply position at delisting time creates a permanent ghost leg, and the borrow gate cannot distinguish it from live collateral.

### Recommendation
On the refresh paths, treat a missing listing as revocation rather than "skip": in `restamp_listed_supply_ltv` and `sync_account_thresholds`, when `cached_spoke_asset` returns `None`, zero the leg's `loan_to_value` (and, gated by the same `clears_min_hf` logic, its `liquidation_threshold`/`bonus`/`fees`) or exclude unlisted legs from `calculate_account_risk_totals` weighting while still allowing exit and seizure. This mirrors the upstream fix — validate the "parent" (listing existence) before trusting cached child records.

### Proof of Concept
1. Alice supplies USDC into spoke S and borrows ETH; her USDC leg is stamped `ltv=7600, lt=8000`.
2. Governance removes USDC from spoke S via the admin path that calls `storage::remove_spoke_asset` (listing revoked — the "domain revocation").
3. Anyone calls `update_account_threshold(caller, true, [alice_id])` → `sync_account_thresholds` → `cached_spoke_asset(S, USDC)` returns `None` → leg skipped; stored `ltv=7600, lt=8000` remain (params.rs:182-185). The same skip applies to every future borrow/withdraw gate via `restamp_listed_supply_ltv` (params.rs:44-50).
4. Alice calls `borrow` again: `enforce_post_pool_solvency` computes `ltv_collateral` from the stored tuple (totals.rs:190-192), so she keeps ~76% borrowing power on the delisted USDC and draws fresh debt the protocol intended to forbid. Her HF likewise keeps the stale 8000 LT, blocking or shrinking liquidation.

Note: I verified the skip-on-unlisted logic and the unconditional use of stored weights; I did not fully trace `update_or_remove_supply_position`'s removal condition, but it is unreachable for unlisted legs since they never enter the refresh branch.