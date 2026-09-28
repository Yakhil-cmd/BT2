### Title
i128 overflow in `scaled_to_original` permanently freezes a market before the borrow-index cap can engage - (File: common/src/rates/simulate.rs)

### Summary
The bug class in ALPINE-CVE-2017-12177 is an integer overflow that crashes the affected component. XOXNO Lending has a directly analogous overflow: every interest-accrual step computes `borrowed * borrow_index` and `supplied * supply_index` via `scaled_to_original` (`Ray::mul` → `mul_div_half_up`), which panics with `MathOverflow` when the RAY-scaled value no longer fits `i128`. Because accrual runs before every user-facing verb and the index cap `MAX_BORROW_INDEX_RAY = 1e36` engages only *after* this multiplication, a large, high-utilization market crosses the `i128` value ceiling first and is then permanently frozen — no repay, withdraw, or liquidation can ever execute again.

### Finding Description
`accrue_step` in `common/src/rates/simulate.rs:60-61` calls `scaled_to_original(env, borrowed, borrow_index)` and `scaled_to_original(env, supplied, supply_index)` on every compounding chunk. `scaled_to_original` (`common/src/rates/scaling.rs:14`) is `scaled.mul(env, index)` = `mul_div_half_up(env, shares, index, RAY)`. When the product/quotient exceeds `i128::MAX`, `to_i128` panics with `GenericError::MathOverflow` (`common/src/math/fp_core.rs:148-159`).

`update_borrow_index` (`common/src/rates/index.rs:13-19`) does clamp the *index* at `MAX_BORROW_INDEX_RAY = 1e36`, but it multiplies first and clamps after — and, more importantly, it runs *after* the `scaled_to_original` calls that overflow. So the cap never gets a chance to stop accrual: the panic happens on line 60-61 of `accrue_step`, before `update_borrow_index` is reached.

`global_sync` (`contracts/pool/src/interest.rs:20-33`) runs this loop unconditionally at the top of every mutating pool operation (supply, borrow, withdraw, repay, liquidate, seize, net_settle, flash paths, claim_revenue). Once the market's scaled value crosses `i128::MAX` (~`1.7e38` RAY units, i.e. ~`1.7e11` whole-token value at index 1.0, or `1e9` whole tokens at index ~170), every subsequent call reverts.

The repository's own harness test proves the sequence end-to-end (`tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:315-361`): a market holding `1e9` whole tokens at 18 decimals, ~98% utilization on the XLM rate curve, reaches `MATH_OVERFLOW` from `update_indexes` after a few years, with `borrow_index < MAX_BORROW_INDEX_RAY` (cap never engaged), and `withdraw`/`repay` subsequently revert with the same error.

### Impact Explanation
Permanent freezing of all funds in the affected market book. Suppliers cannot withdraw, borrowers cannot repay, liquidators cannot liquidate, and protocol revenue cannot be claimed, because `global_sync` panics before any state transition. Every token supplied to that hub/token book is bricked permanently — there is no escape path since the overflow is in the shared accrual preamble, not in a specific verb. This matches the "permanent freezing of funds" / "contract unable to operate" acceptance criteria, and it is a fail-*dead* condition, not a fail-closed guard: no index cap or guard engages.

### Likelihood Explanation
Medium. Reaching the cliff requires no privileged action: any unprivileged address can `supply` and `borrow` (capped only by listing caps, which the test lifts to the representable domain), and `update_indexes` is permissionless. However it needs a very large market (~`1e9` whole tokens at 18 decimals, or smaller balances if accrual drives the index to ~170x) *and* sustained ~98% utilization for multiple years on a steep rate curve. The 40-year horizon in the test and the test's own note that "the bound in docs/reference/formulas.md is wrong" show the documented numeric-limit bound understates the risk — the value ceiling is hit before the index cap that was supposed to bound growth. Realistic on-chain markets are unlikely to reach this scale quickly, but nothing in the protocol prevents it.

### Recommendation
Compute the pre-clamp index and guard the valuation before multiplying:
- In `accrue_step`, evaluate `update_borrow_index`/`update_supply_index` first, and short-circuit `scaled_to_original` when `borrow_index`/`supply_index` has reached `MAX_*_INDEX_RAY` (at the cap no further interest accrues anyway, so utilization for the step can reuse stored values or be skipped).
- Alternatively, add a saturating `scaled_to_original_saturating` (mirroring `mul_div_floor_saturating` already used in `calculate_scaled_cap`) for the accrual-time utilization estimate, so a market pinned at the index ceiling keeps operating rather than trapping.
- Enforce a lower listing-side ceiling: `require_cap_within_asset_domain` / supply-cap validation should bound `cap × 10^(27-d) × MAX_*_INDEX_RAY / RAY ≤ i128::MAX` so the representable domain is unreachable rather than merely slow to reach.

### Proof of Concept
Reachable path for a single unprivileged address:

1. `controller.supply(asset=BIG18, amount=1_000_000_000 * 10^18, ...)` — mints scaled supply shares near the representable domain.
2. With collateral on another market, `controller.borrow(asset=BIG18, amount≈0.98*supply, ...)` — pins utilization ~98% on the XLM curve (steep segment).
3. Anyone calls `controller.update_indexes(BIG18)` (or any verb, which accrues first) once per elapsed period.

Each accrual runs `accrue_step` → `scaled_to_original(borrowed, borrow_index)` → `Ray::mul` → `mul_div_half_up` → `to_i128` panic `MathOverflow` once `borrowed * borrow_index / RAY > i128::MAX`, i.e. `borrow_index ≈ 170×RAY` for a `1e9`-token book. After the first failing accrual:

```text
update_indexes(BIG18) → MathOverflow
withdraw(BOB, BIG18, 1) → MathOverflow   // accrues first
repay(ALICE, BIG18, ...) → MathOverflow  // accrues first
borrow_index < MAX_BORROW_INDEX_RAY      // cap never engaged
```

This is exactly what `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` asserts at `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:321-356`: `try_update_indexes_for`, `try_withdraw_raw`, and `try_repay` all revert with `errors::MATH_OVERFLOW` while `borrow_index < MAX_BORROW_INDEX_RAY`.