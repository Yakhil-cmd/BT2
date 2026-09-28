### Title
Whale-scale accrued debt overflows before the borrow-index cap and permanently freezes a market - (File: common/src/rates/simulate.rs)

### Summary
`accrue_step` calculates the market’s total borrowed and supplied value before applying the `MAX_BORROW_INDEX_RAY` index cap. For a sufficiently large market at sustained high utilization, `borrowed * borrow_index / RAY` can exceed `i128::MAX` while `borrow_index` is still below the cap. The resulting `MathOverflow` aborts accrual before `last_timestamp` advances, so every subsequent operation that syncs the market fails.

### Finding Description
Pool mutations load market state through `synced_market`, which invokes `interest::global_sync` before repay, withdraw, borrow, supply, liquidation-related operations, and other accounting actions. `global_sync` calls `accrue_step` for each accrual interval.

Inside `common/src/rates/simulate.rs`, `accrue_step` first evaluates:

- `scaled_to_original(borrowed, borrow_index)`
- `scaled_to_original(supplied, supply_index)`

`scaled_to_original` performs fixed-point multiplication and panics with `MathOverflow` when the resulting RAY value exceeds `i128`.

Only after these total-value calculations does `update_borrow_index` clamp the newly projected borrow index to `MAX_BORROW_INDEX_RAY`. Therefore, the cap does not protect the multiplication of an already-large scaled book by the existing index.

The issue is demonstrated by `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs`: a market holding one billion 18-decimal tokens at 98% utilization eventually returns `MATH_OVERFLOW` from `update_indexes`; the stored borrow index remains below `MAX_BORROW_INDEX_RAY`; and subsequent `withdraw` and `repay` calls fail for the same reason.

### Impact Explanation
This permanently freezes all funds and debt actions in the affected market:

- suppliers cannot withdraw;
- borrowers or third parties cannot repay;
- liquidations cannot progress through the normal pool path;
- new borrows and supply mutations fail;
- revenue and bad-debt flows that require accrual also fail.

Because the panic occurs before `last_timestamp` advances, waiting does not let the market skip the overflowing interval. An unprivileged caller who can create or occupy a sufficiently large high-utilization book can therefore cause permanent loss of access to all users’ funds in that market.

### Likelihood Explanation
The attack requires an extremely large market: approximately `1e27` raw units of an 18-decimal asset supplied and about 98% borrowed, under a steep rate configuration and enough collateral to support the borrow. It also requires years of index growth unless the market is already large enough to be near the representable bound.

These requirements are economically demanding, but the path is reachable through ordinary `supply`, `borrow`, and permissionless `update_indexes` calls where market caps and collateral allow the position. The exploit does not require privileged access, malformed input, an oracle manipulation, or control over another account.

### Recommendation
Order accrual so that index growth is clamped before converting scaled shares to underlying value. In particular:

1. Compute and clamp `new_borrow_index` before evaluating total debt at that index.
2. Use saturating or widened total-value calculations where overflow represents economic size rather than a malformed value.
3. Add an explicit invariant that `borrowed * borrow_index / RAY` and `supplied * supply_index / RAY` remain representable for every committed state.
4. Enforce this bound during supply and borrow minting, not merely during accrual.
5. Extend the existing long-horizon regression coverage so the index cap engages before any representability limit can freeze the market.

### Proof of Concept
The repository already contains a reproducer in `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs`, `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap`.

Conceptually:

1. Create or select a listed 18-decimal market whose caps permit a one-billion-token book.
2. Call `supply` with one leg containing `amount = 1_000_000_000 * 10^18`.
3. Supply sufficient collateral in another listed market and call `borrow` for `amount = supplied * 98 / 100`.
4. Advance ledger time until the high-utilization curve grows the stored index toward the representability boundary.
5. Call permissionless `update_indexes(caller, [hub_asset])`.
6. The call returns `MathOverflow` inside `scaled_to_original`.
7. Subsequent `repay`, `withdraw`, and later `update_indexes` calls fail before any state can be committed because they all perform accrual first.