### Title
Unbounded index-scaled debt permanently freezes an overgrown market - (File: common/src/rates/simulate.rs)

### Summary
Interest accrual converts scaled debt back to its full RAY-denominated value before enforcing any representability bound. When `borrowed_scaled * borrow_index / RAY` exceeds `i128::MAX`, `scaled_to_original` panics with `MathOverflow`. Because every pool mutation synchronizes interest before applying the requested operation, the market thereafter cannot be repaid, withdrawn from, liquidated, or otherwise updated.

### Finding Description
`accrue_step` unconditionally unscales the stored scaled borrow balance using the stored borrow index at `common/src/rates/simulate.rs:60`. That calls `scaled_to_original`, which performs checked `Ray` multiplication at `common/src/rates/scaling.rs:14-16` and panics on overflow.

The pool then compounds the index and computes rewards using similarly unscaled totals at `common/src/rates/index.rs:80-83`. Although `update_borrow_index` caps the index itself at `MAX_BORROW_INDEX_RAY` at `common/src/rates/index.rs:13-18`, it does not ensure that `borrowed_scaled * borrow_index` remains representable.

All pool mutations load a synchronized market: `ops::load_leg` invokes `synced_market`, and `synced_market` calls `interest::global_sync` before the operation-specific logic at `contracts/pool/src/ops/mod.rs:30-46`. `global_sync` invokes `accrue_step` for each elapsed chunk at `contracts/pool/src/interest.rs:20-52`.

Once the invariant is crossed:

- `controller.update_indexes(caller, assets)` fails, because it forwards the market keys to pool `update_indexes`.
- `withdraw` fails before burning supply shares.
- `repay` fails before burning debt shares.
- liquidation and bad-debt paths also fail because they use the same synchronized market loader.
- `recapitalize` or direct token transfers cannot remove the offending scaled debt/index pair.

The repository already contains a regression test demonstrating this exact condition at `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:315-356`. The test reaches `MathOverflow` while `borrow_index < MAX_BORROW_INDEX_RAY`, then confirms that both withdrawal and repayment fail with the same error.

### Impact Explanation
This can permanently freeze all supplier funds in the affected market. Borrowers cannot repay, suppliers cannot withdraw, liquidators cannot liquidate, and bad debt cannot be cleaned because the same failing accrual is executed before each operation. The affected market is effectively bricked despite still holding user funds.

This maps to the report's crash-on-specially-reachable-state class: a state accepted through normal market operations later makes the validation/accrual path abort on every subsequent invocation.

### Likelihood Explanation
Medium. The trigger requires an extremely large scaled debt balance and a sufficiently high borrow index, rather than a single malformed argument. In the demonstrated scenario, an 18-decimal market holds roughly `1e27` base units of supply and sustains approximately 98% utilization until the index grows enough for `borrowed_scaled * borrow_index` to exceed `i128::MAX`. This requires substantial capital and favorable market configuration, but it can be established through normal unprivileged supply and borrow flows. After that, any authorized caller can trigger the permanent failure through `update_indexes`.

### Recommendation
Bound the scaled market state relative to the current and projected indexes, rather than only capping the index. In particular:

1. Before updating `borrow_index`, compute the maximum scaled debt that remains representable under the projected index.
2. Use checked or saturating unscale operations for aggregate debt and supply valuation.
3. If the index reaches its cap or the aggregate value reaches the `i128` boundary, transition the market into a bounded-terminal accrual state instead of panicking.
4. Ensure `repay`, `withdraw`, liquidation, and bad-debt cleanup remain executable after the bound is reached.
5. Add the existing long-horizon regression test to the required test suite so the market cannot silently re-enter the panic domain.

### Proof of Concept
The checked-in test demonstrates the issue:

```text
Market: BIG18, decimals = 18
Principal supplied: 1_000_000_000 * 10^18 base units
Debt: 98% of supplied principal
Rate model: xlm_curve()
```

Sequence:

1. An account supplies the large `BIG18` balance through the controller supply path.
2. A sufficiently collateralized account borrows 98% of that market through the controller borrow path.
3. Ledger time advances while utilization remains high.
4. Any caller invokes:

```text
update_indexes(caller, [HubAssetKey { hub_id, asset: BIG18 }])
```

5. `global_sync -> accrue_step -> scaled_to_original` panics with `MathOverflow` before the index reaches `MAX_BORROW_INDEX_RAY`.
6. Subsequent `withdraw` and `repay` calls fail with the same `MathOverflow`, proving that the market cannot recover through its normal exit or repayment paths.

The concrete executable reproduction is `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` in `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:321-356`.