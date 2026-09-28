### Title
`swap_debt` refinances debt into a destination asset with no spoke-listing, borrowability, frozen, or hub-active check on the new debt asset - (File: contracts/controller/src/strategies/swap_debt.rs)

### Summary

The Craft CMS analog is a destination-side authorization gap: `actionMoveToSection()` gates only the *view* of the destination and the *move* of the source, never the *write into* the destination. `Controller::swap_debt` has the same shape. It gates the source side (`require_hub_active(existing_debt.hub_id)`, `get_debt_position_or_panic` on `existing_debt`, `require_owner_or_delegate`) but performs **no validation at all on `new_debt`** before minting debt in it via `borrow_into_controller`: no spoke-listing check, no `is_borrowable` flag check, no `frozen`/`paused` check, and not even `require_hub_active(new_debt.hub_id)`. Every sibling strategy that introduces a new debt/supply leg explicitly gates its destination — `multiply`, `flash_position`, and `migrate_blend` call `require_can_borrow`, and `swap_collateral` calls `require_can_supply` on the destination before touching the source — but `process_swap_debt` omits the equivalent call entirely.

### Finding Description

In `contracts/controller/src/strategies/swap_debt.rs:28-87`, `process_swap_debt` performs:

- `require_hub_active(env, existing_debt.hub_id)` — source hub only (line 44).
- `get_debt_position_or_panic(env, &account, existing_debt)` — source-side gate, equivalent to Craft's `Entry::canMove()` (line 50).
- `borrow_into_controller(env, &mut account, new_debt, new_debt_amount, true, ...)` — privileged sink that mints RAY debt shares on `new_debt` and draws pool liquidity (lines 55-63).

Compare with `contracts/controller/src/strategies/multiply.rs`, `flash_position.rs`, and `migrate_blend.rs`, which each call `positions::require_can_borrow` (defined at `contracts/controller/src/positions/mod.rs:201-213`) to enforce `require_listed_unhalted_config` + `is_borrowable` on the asset being borrowed into, and with `swap_collateral.rs:50`, which calls `require_can_supply` on the destination collateral with the comment "Check the destination before withdrawing existing collateral." `swap_debt` has no corresponding `require_can_borrow(env, &mut cache, account.spoke_id, new_debt)` and no `require_hub_active(env, new_debt.hub_id)`, so the destination leg is completely ungated at the spoke/hub level.

Concretely, an unprivileged account owner/delegate can:

1. Hold a debt position in a normal asset (`existing_debt`).
2. Call `controller::swap_debt(caller, account_id, existing_debt, amount, new_debt, swap)` where `new_debt` targets a spoke asset with `is_borrowable = false`, a `frozen`/`paused` spoke listing, an asset listed in a *different* spoke than the account's, or an asset on an inactive hub.
3. The controller mints the new debt and repays the old, so the account now carries debt in an asset that governance deliberately forbade borrowing.

The `true` argument passed to `borrow_into_controller` and the per-market debt cap in the pool may still apply, but the spoke-level listing flags — the exact mechanism governance uses to wind down or ring-fence assets (`can_borrow`, `frozen`, `paused`) — are bypassed, and cross-hub passthrough (`Matching assets across hubs pass through`, line 27) means the destination hub's active flag is never consulted either.

*Caveat:* whether `borrow_into_controller` internally re-checks spoke gates could not be fully verified in this pass; however, the uniform pattern of explicit `require_can_borrow`/`require_can_supply` calls in every other strategy strongly indicates the gate is the caller's responsibility and is missing here.

### Impact Explanation

Breaks the spoke-level authorization model: governance flags (`is_borrowable`, `frozen`, `paused`, per-spoke listing) exist to fence off assets — e.g., freezing borrowing of a deprecating or depegged asset. `swap_debt` lets any account owner or delegate create fresh debt in such an asset anyway, draining pool liquidity in a market that is supposed to be borrow-closed and concentrating protocol exposure in an asset governance marked as unsafe to borrow. This is theft-adjacent/protocol-insolvency surface: borrowing against a frozen asset that is mid-wind-down can leave the pool holding debt denominated in an asset with impaired liquidation or pricing, i.e., bad-debt/insolvency risk funded by suppliers.

### Likelihood Explanation

Reachable by any unprivileged address that owns (or is an active delegate of) an account with an existing debt position — `swap_debt` is a `caller-auth` permissionless entrypoint. Preconditions: a spoke asset exists with `is_borrowable = false`/`frozen`/`paused` (a routine governance wind-down state) or on an inactive hub, and a swap route (or same-asset cross-hub passthrough with empty `steps`) exists between the source and destination assets. No privileged role, oracle manipulation, or race is required.

### Recommendation

Mirror the destination-side gate used by every sibling strategy: before `borrow_into_controller`, call `config::require_hub_active(env, new_debt.hub_id)` and `positions::require_can_borrow(env, &mut cache, account.spoke_id, new_debt)` so the destination debt asset must be listed, unhalted, and borrowable in the account's spoke — the same way `swap_collateral` calls `require_can_supply` on its destination before touching the source.

### Proof of Concept

```rust
// contracts/controller/src/strategies/swap_debt.rs
config::require_hub_active(env, existing_debt.hub_id); // line 44: source hub only
// MISSING: config::require_hub_active(env, new_debt.hub_id);
// MISSING: positions::require_can_borrow(env, &mut cache, account.spoke_id, new_debt);
let amount_received = borrow_into_controller(env, &mut account, new_debt, ...); // lines 55-63
```

Test sketch (harness): build `three_asset_usdc_eth_wbtc`, set WBTC spoke asset `can_borrow = false` (or `frozen = true`, as in `test_swap_collateral_rejects_frozen_destination`), give ALICE ETH debt, then `try_swap_debt(ALICE, "ETH", amount, "WBTC", steps)` — expected `ASSET_NOT_BORROWABLE`/`SPOKE_ASSET_FROZEN`, actual success, leaving ALICE with WBTC debt in a borrow-closed market.