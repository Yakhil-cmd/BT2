### Title
A liquidatable borrower can self-close via `repay_debt_with_collateral` and skip the liquidation bonus and protocol fee - (File: contracts/controller/src/strategies/repay_debt_with_collateral.rs)

### Summary
The Unstoppable bug class — "close a liquidatable position before anyone liquidates it to evade the liquidation penalty" — maps onto `Controller::repay_debt_with_collateral`. A borrower whose account is liquidatable (`health_factor < 1 WAD`) can repay its whole debt using its own collateral at market price, with no liquidation bonus and no `liquidation_fees` cut, then withdraw the remainder via `close_position: true`. The only solvency gate in this path, `require_post_pool_risk_gates`, returns early once the account is debt-free, so an underwater account exits cleanly and the penalty is never paid.

### Finding Description
`repay_debt_with_collateral` has two settlement paths at `contracts/controller/src/strategies/repay_debt_with_collateral.rs:57-79`: same-market netting (`net_settle_collateral_against_debt`, empty swap) or withdraw-and-swap (`repay_via_collateral_swap` → `withdraw_and_swap_from_supply` → `repay_debt_from_controller`). Neither path checks `is_liquidatable`/`can_be_liquidated` before mutating positions, and neither applies the liquidation bonus or `liquidation_fees` — the repayment retires debt at face value.

With `close_position: true`, lines 81-89 then require zero remaining borrow positions and call `execute_withdraw_all`, sending every remaining supply position to the caller — functionally identical to Unstoppable's `close_position`.

Finalization runs `strategy_finalize` → `require_post_pool_risk_gates` (`contracts/controller/src/risk/validation.rs:29-32`), which skips all checks when `account.debt_free()`. So a fully self-repaid liquidatable account passes, whereas a *partial* unwind that leaves debt still hits `health_factor >= Wad::ONE` at validation.rs:49-53 and reverts `InsufficientCollateral`. Plain `withdraw` is likewise gated (`test_withdraw_rejects_exceeding_hf`), so the only unpenalized full exit is this repay-with-collateral close.

Contrast with `liquidate`: the liquidation plan prices seizure at `value × (1 + bonus)` where `bonus` comes from the HF-based curve, and `liquidation_fees` on the bonus are reclassified as protocol revenue (docs/reference/invariants.md INV-LIQ-02). Self-closing at market price pays neither.

### Impact Explanation
Lost protocol revenue and lost liquidator incentive: for every account the borrower front-runs with `repay_debt_with_collateral(close_position = true)`, the `liquidation_fees` share of the bonus never reaches revenue and the bonus is never paid. Lenders' principal is not impaired — the debt is repaid in full — so the impact is confined to evaded penalty/fee yield rather than bad debt or insolvency. That bounds this at Medium rather than High.

### Likelihood Explanation
Reachable by any unprivileged owner or active delegate of a liquidatable account in a single transaction. The strongest variant needs no router at all: when the collateral and debt are the same hub asset, `collateral == debt` requires empty `swap` bytes and nets balances internally (lines 57-67), so no external liquidity or quote is needed. For cross-asset closes the borrower needs a working swap route and enough collateral value to cover the debt; if collateral can't cover the full debt, the call reverts on `CannotCloseWithRemainingDebt` (close path) or `InsufficientCollateral` (partial path). The account must also not be insolvent enough for `clean_bad_debt` to have already socialized it.

### Recommendation
Gate the close on liquidation status, mirroring the suggested fix for Unstoppable:

```diff
pub(crate) fn process_repay_debt_with_collateral(...) {
    require_authorized_caller(env, caller);
+   // Reject self-close while liquidatable so the bonus/fees cannot be evaded.
+   assert_with_error!(env, !views::can_be_liquidated(env, account_id), CollateralError::InLiquidation);
    ...
}
```

Alternatively, allow the repay but charge the liquidation curve bonus and `liquidation_fees` on the collateral consumed when the pre-action health factor is below `WAD`.

Caveat: the codebase explicitly documents that "owners can self-liquidate" (INV-LIQ-01), so the protocol already permits an owner to run `liquidate` on its own account — the distinguishing harm here is purely the unpaid fee/bonus. If the design intent is that self-service repayment at market price is always allowed, this is a documented trade-off rather than a defect; flag it for an explicit ADR decision either way.

### Proof of Concept
1. Alice supplies 10,000 USDC and borrows 3 ETH (as in `tests/test-harness/tests/controller/liquidation.rs`).
2. `set_price("USDC", usd_cents(40))` → `is_liquidatable(alice) == true` (`health_factor < WAD`).
3. Before any liquidator acts, Alice calls `repay_debt_with_collateral(caller: alice, account_id, collateral: USDC, collateral_amount: enough to cover debt via swap to ETH, debt: ETH, swap: route, close_position: true)`; or, if she supplied and borrowed the same token, the same-asset netting path with empty `swap`.
4. All debt is retired at market value, `account.borrow_positions` empties, `execute_withdraw_all` returns remaining USDC to Alice, and `require_post_pool_risk_gates` short-circuits on `debt_free()`.
5. Result: account closed with zero bonus seized and zero `liquidation_fees` to revenue — the penalty a `liquidate` call would have charged is fully evaded.

Note: I could not run the harness to confirm the exact post-close revenue delta; the code path (debt-free early return in the gate, no bonus logic in the repay-with-collateral legs) supports the claim directly.