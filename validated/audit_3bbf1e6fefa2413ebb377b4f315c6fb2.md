### Title
`i128` overflow in `scaled_to_original` during accrual permanently freezes a high-rate market before the borrow-index cap can engage - (File: common/src/rates/scaling.rs)

### Summary
The accrual path computes `borrowed * borrow_index` via `scaled_to_original` before the `MAX_BORROW_INDEX_RAY` cap is applied. On a whale-scale market at sustained high utilization the product overflows `i128` and panics with `MathOverflow`. Because every user-facing verb (`supply`, `withdraw`, `borrow`, `repay`, `liquidate`, `clean_bad_debt`, flash paths, `update_indexes`) runs accrual first, the panic bricks the market permanently — the existing cap on the borrow index never gets a chance to engage because the overflow happens in the *value* computation, not the index update.

### Finding Description
`accrue_step` (`common/src/rates/simulate.rs:60-61`) computes utilization from unscalded balances:

```rust
let borrowed_original = scaled_to_original(env, borrowed, borrow_index);
let supplied_original = scaled_to_original(env, supplied, supply_index);
```

`scaled_to_original` is `Ray::mul` → `fp_core::mul_div_half_up` (`common/src/math/fp_core.rs`), which widens to `I256` for the product but the *result* must still fit `i128`; otherwise it panics with `GenericError::MathOverflow`. The debt ceiling is therefore `borrowed_ray * borrow_index <= i128::MAX`, i.e. roughly `i128::MAX / RAY ≈ 1.7e11` whole tokens times the index — while `update_borrow_index` (`common/src/rates/index.rs:13-18`) caps the index at `MAX_BORROW_INDEX_RAY` only *after* this multiplication has already run. Once `borrowed * borrow_index > i128::MAX`, every subsequent accrual panics, and `global_sync` (`contracts/pool/src/interest.rs:20-33`) is invoked at the top of every state-mutating pool operation, so no exit path remains. `repay`, `withdraw`, `liquidate`, `clean_bad_debt`, and even `recapitalize` all hit the same panic.

The bug class mirrors CVE-2018-1000810: an unbounded multiplicative growth (`str::repeat(n)` → `index * scaled_amount`) over an `i128` domain, where the magnitude is driven by user-influenced state (pool size) rather than validated against the representable bound. The codebase's own test demonstrates the failure: `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` (`tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:321-356`) shows a 98%-utilization market hitting `MATH_OVERFLOW` — `try_withdraw_raw` and `try_repay` both revert, and the comment notes the documented bound in `docs/reference/formulas.md` understates how early the cliff arrives.

### Impact Explanation
Permanent freezing of all funds in the affected market: suppliers cannot withdraw, borrowers cannot repay, liquidators cannot liquidate, and `update_indexes` itself reverts, so the freeze is unrecoverable by any caller including governance-initiated flows that touch that market. This is exactly the "permanent freezing of funds" / "contract unable to operate" impact class.

### Likelihood Explanation
Requires a market whose scaled book approaches `i128::MAX / RAY` (~1.7e11 whole tokens at 18 decimals, more at lower decimals) combined with a borrow index that has grown ~170x — reachable within the listed cap domain on a large high-supply asset at sustained steep-curve utilization, since `supply`, `borrow`, and `update_indexes` are all permissionless and an attacker can push utilization to the steep segment. It is not triggerable on demand on a small market — time must genuinely elapse — but once the state condition exists, any unprivileged `update_indexes` call delivers the freeze and no recovery path exists, making it a latent guaranteed-freeze rather than an avoidable edge case. Severity: High.

### Recommendation
Order the cap before the multiplication: clamp `borrow_index` to `min(borrow_index * factor, MAX_BORROW_INDEX_RAY)` semantics such that the *value* computation saturates rather than panics — e.g., compute `borrowed_original` via a saturating `mul_div_floor_saturating`-style variant, or short-circuit accrual when `borrowed * borrow_index` would exceed `i128::MAX` (cap the index so the product stays representable, mirroring how `protocol_fee_shares` already clamps to `i128::MAX - supplied` in `common/src/rates/index.rs:94-99`). Also enforce per-market supply/borrow caps strictly below `i128::MAX / RAY / MAX_BORROW_INDEX_RAY` at listing so the overflow domain is unreachable, and add an emergency `apply_bad_debt`-style index write-down that does not call `scaled_to_original` first so a stuck market can still be unwound.

### Proof of Concept
Codified by the existing harness test (`tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:321-356`):

1. Attacker supplies `1e9 * 10^18` units of an 18-decimal asset (within `max_cap_for_decimals`) and borrows 98% of it, pinning the curve at its steep segment (`max_borrow_rate` ~2 RAY).
2. As years elapse, permissionless `update_indexes` calls grow `borrow_index` normally via `accrue_step`.
3. Once `borrowed_ray * borrow_index > i128::MAX` — which occurs at an index of only ~174x, far below `MAX_BORROW_INDEX_RAY` — the `scaled_to_original` call in `accrue_step` panics with `MathOverflow`.
4. The market is permanently frozen: `withdraw(1)` reverts, `repay` reverts, `liquidate` reverts, and the index cap can never engage because the panic precedes it.