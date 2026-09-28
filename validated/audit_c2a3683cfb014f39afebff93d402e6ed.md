### Title
`flash_position` hard-fails on any under-delivering debt token because `mint_and_forward` asserts `measured == reported` - (File: contracts/controller/src/strategies/flash_position.rs)

### Summary
The codebase deliberately uses measured receipts (`transfer_amount_measured`, `balance_delta_since`) everywhere instead of trusting reported transfer amounts, which is exactly the fix the external report recommends. One spot breaks that pattern: `mint_and_forward` in `contracts/controller/src/strategies/flash_position.rs:281-282` asserts the controller's measured balance increase equals the amount the pool reported it sent (`measured == reported`). For a debt asset whose `transfer` under-delivers (fee-on-transfer / deflationary token), the pool debits cash and mints debt for the full amount while the controller receives less, so the assertion panics with `GenericError::InternalError` and the entire `flash_position` call reverts — for every amount, every user, forever, on that market.

### Finding Description
`flash_position` mints fee-free debt into controller custody via `borrow_into_controller` (which calls `pool_borrow_call` → `LiquidityPoolClient::borrow` / `create_strategy`), snapshots the controller balance before, and then requires the delta to equal the pool-returned `actual_amount`:

```rust
let reported = borrow_into_controller(env, account, debt, amount, false, PositionAction::FlashPos, cache);
let measured = balance_delta_since(env, &debt.asset, &controller, before);
assert_with_error!(env, measured == reported, GenericError::InternalError);
```

The pool side transfers `net_transfer` out with a plain `token.transfer` (`contracts/pool/src/ops/withdraw.rs:48`, `cache.transfer_out`), and reports `actual_amount` as the gross/asset-unit figure, not a measured receipt. The protocol's own test suite registers fee-on-transfer markets (`with_fee_on_transfer_market`, `SHORTFALL_BPS` in `tests/test-harness/tests/controller/liquidation_under_delivering_debt_token.rs`), showing under-delivering assets are in-scope market candidates. With such a token, `measured < reported` on every call, so `mint_and_forward` always reverts. All other settlement paths (`legs.rs::repay_debt_from_controller`, `markets.rs::claim_revenue_for_asset`, liquidation legs, router `dispatch_hop`) credit `post - pre` rather than asserting equality, so this assert is inconsistent with the documented INV-ACCT-03 design.

### Impact Explanation
`flash_position` is permanently unusable for any hub market whose token under-delivers on transfer — a whole strategy/entrypoint is dead for that market (temporary freezing of functionality / contract unable to operate for that asset class), matching the original Medium impact ("provider may not work at all for some tokens"). The revert happens after the pool has already minted debt internally within the same transaction, so the whole op rolls back; no funds are lost, but the feature is bricked.

### Likelihood Explanation
Certain — not probabilistic — once any listed market uses a fee-on-transfer or otherwise under-delivering token. Any unprivileged caller invoking `flash_position` with that debt asset hits `InternalError` unconditionally. Likelihood depends only on such a token being whitelisted, which the codebase explicitly supports testing for.

### Recommendation
Drop the `measured == reported` equality check in favor of `measured > 0` plus crediting `measured` (and forwarding `measured`, which is already done), or, if the reconciliation is meant to catch pool mis-accounting, compare `measured >= reported`/`measured <= reported` directionally and reconcile the position against `measured`. At minimum, document and gate the market whitelist to reject under-delivering tokens if the assert is intentional.

### Proof of Concept
1. Governance/whitelist lists market `(hub, T)` where `T` is a fee-on-transfer token taking e.g. 10% on every `transfer` (the harness supports this via `with_fee_on_transfer_market`).
2. Alice supplies collateral in a normal market and calls `controller.flash_position` (or `multiply`-style strategy using `mint_and_forward`) requesting debt amount `X` of `T`.
3. Pool `borrow` mints debt, debits cash `X`, `transfer`s `X` to the controller; controller receives `0.9X`.
4. `balance_delta_since` returns `0.9X`; `reported == X`; `assert_with_error!(measured == reported)` → `GenericError::InternalError`; the whole transaction reverts.
5. Repeat with any `X` and any caller — `flash_position` can never settle for `T`, while `supply`/`borrow`/`repay`/`liquidate` still work for it via measured-delta accounting.