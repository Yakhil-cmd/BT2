### Title
Debt-value overflow in accrual permanently freezes a market — the `MAX_BORROW_INDEX_RAY` cap never engages - (File: common/src/rates/simulate.rs)

### Summary
Analogous to a reachable assertion in libtiff's `tiffcp`, the pool's accrual step hits a reachable arithmetic panic inside `scaled_to_original` whenever `borrowed * borrow_index` exceeds `i128::MAX`. Because `accrue_step` computes the unscaled debt *before* `update_borrow_index` applies the `MAX_BORROW_INDEX_RAY` clamp, the index cap cannot prevent the freeze: the panic is on the RAY-denominated value, not the index. Every controller verb (supply, borrow, withdraw, repay, liquidate, `update_indexes`) accrues the market first, so once the debt value crosses the RAY-value ceiling the market is permanently bricked — no repay, no withdraw, no liquidation. A checked-in test already demonstrates this end-to-end.

### Finding Description
`accrue_step` opens with:

```rust
let borrowed_original = scaled_to_original(env, borrowed, borrow_index); // simulate.rs:60
```

`scaled_to_original` is `scaled.mul(env, index)` (`common/src/rates/scaling.rs:14-16`), and `Ray::mul` panics with `GenericError::MathOverflow` when the product exceeds `i128::MAX` (`common/src/math/fp_core.rs:117`). Only *after* this panic-prone valuation does `update_borrow_index` clamp the index to `MAX_BORROW_INDEX_RAY` (`common/src/rates/index.rs:13-19`) — and the docs acknowledge the gap: "Debt-value overflow can still revert accrual before that ceiling is reached" (`docs/reference/invariants.md`, INV-IDX-01).

The same pattern repeats inside the step: `calculate_supplier_rewards` multiplies `borrowed` by the new index (`index.rs:80-81`), so even if line 60 survived, the very next computation re-triggers the panic while `borrowed > i128::MAX / borrow_index`.

`global_sync`/`simulate_update_indexes` run this on every market touch; there is no early-exit when the index is already at the cap, and no `try_*` variant is used on the value path.

### Impact Explanation
Permanent freezing of funds. Once `borrowed * borrow_index` overflows `i128`:

- `update_indexes` reverts, so no user call can advance the market;
- `withdraw`, `repay`, `liquidate`, `clean_bad_debt` all accrue first and revert identically;
- suppliers' tokens in that (hub, token) book are frozen forever, including the pool cash physically held there.

The harness test `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` (`tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:316-362`) proves this: `try_withdraw_raw` and `try_repay` both fail with `MATH_OVERFLOW`, and `last.borrow_index < MAX_BORROW_INDEX_RAY` confirms the cap never engaged.

### Likelihood Explanation
Reachable by an unprivileged address but conditional. The trigger requires only `supply` + `borrow` (both permissionless) to push utilization high on a large book, then time. However, the debt's scaled RAY value must approach `i128::MAX` (~1.7e38), i.e. a whale-scale market (~10^27 raw units × index growth), and the index must grow well past 1.0 over years of sustained high utilization before the overflow occurs. It is not triggerable on demand at realistic book sizes, which caps severity at Medium — consistent with the source advisory.

### Recommendation
Cap before converting, not after. In `accrue_step`, clamp `borrow_index` to `MAX_BORROW_INDEX_RAY` *before* `scaled_to_original`, and/or use a saturating unscale (`mul_div_floor_saturating` as in `update_supply_index`/`protocol_fee_shares`) for the utilization read at `simulate.rs:60-61` — utilization at saturating debt is already 100%+, so saturation is semantically correct. Add a short-circuit in `global_sync` when `borrow_index == MAX_BORROW_INDEX_RAY` so capped markets keep processing withdrawals/repayments without re-multiplying debt.

### Proof of Concept
The checked-in test is the PoC:

1. `supply_raw(BOB, "BIG18", 10^9 * 10^18)`; `borrow_raw(ALICE, "BIG18", 98% of it)` — permissionless calls.
2. Advance ledger time year-by-year; each `update_indexes` calls `global_sync` → `accrue_step`.
3. Once `borrowed * borrow_index > i128::MAX`, `scaled_to_original` panics `MATH_OVERFLOW` while `borrow_index < MAX_BORROW_INDEX_RAY` (test asserts exactly this).
4. `withdraw(BOB, 1)` and `repay(ALICE, 1.0)` both revert `MATH_OVERFLOW` — the market is frozen permanently.