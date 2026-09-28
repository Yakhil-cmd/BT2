### Title
Accrual `scaled * index` overflow permanently freezes a large market before the borrow-index cap can engage - (File: common/src/rates/scaling.rs)

### Summary
Every mutating entrypoint on a market runs interest accrual first (`accrue_step` in `common/src/rates/simulate.rs:51-94`, invoked via `contracts/pool/src/interest.rs::global_sync`). The first thing accrual does is unscale the RAY-denominated books: `scaled_to_original(env, borrowed, borrow_index)` and `scaled_to_original(env, supplied, supply_index)` at `common/src/rates/simulate.rs:60-61`, which is `scaled.mul(env, index)` at `common/src/rates/scaling.rs:14-16`. When the product `scaled_shares * index / RAY` exceeds `i128::MAX`, `Ray::mul` panics with `GenericError::MathOverflow` (`common/src/math/fp_core.rs:108-118`).

The borrow index is capped at `MAX_BORROW_INDEX_RAY` (`common/src/rates/index.rs:13-19`), but the cap is checked *after* the value product is computed. For a book whose scaled supply/debt is large enough that the RAY value ceiling (`i128::MAX`) is reached while `borrow_index < MAX_BORROW_INDEX_RAY`, the accrual panics before the cap can ever engage. Since both indexes are monotone non-decreasing and `borrowed`/`supplied` only grow through accrual, the panic is permanent: `update_indexes`, `supply`, `withdraw`, `borrow`, `repay`, `liquidate`, `clean_bad_debt`, and every other verb on that hub asset all revert forever.

This is the exact analog of the Moloch finding: a value that grows past the integer ceiling (there a maliciously inflated token supply tripping SafeMath inside `internalTransfer`; here a legitimately large RAY-scaled book times a grown index) bricks `processProposal`/`cancelProposal` analogs — `repay`, `withdraw`, `liquidate` — permanently.

### Finding Description
- Supply caps are validated against `max_cap_for_decimals` (`common/src/validation.rs:48-70`), which deliberately permits caps up to `i128::MAX / 10^(27 - decimals)`. For an 18-decimal asset that is ≈1.7e29 base units (≈170 billion whole tokens) — enough for the book's RAY value to reach the `i128` ceiling once the index multiplies it.
- `accrue_step` computes `borrowed_original = borrowed_scaled * borrow_index / RAY` and `supplied_original = supplied_scaled * supply_index / RAY` with panicking `i128`/`I256→i128` arithmetic, before the `MAX_BORROW_INDEX_RAY` clamp in `update_borrow_index` can bound anything.
- Once `borrowed_scaled * borrow_index > i128::MAX` (or the supply side equivalent), every call that accrues panics. The project's own harness test `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` (`tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:320-361`) demonstrates the freeze end-to-end: `update_indexes`, `withdraw`, and `repay` all revert with `MATH_OVERFLOW` while `borrow_index < MAX_BORROW_INDEX_RAY`.

### Impact Explanation
Permanent freezing of funds: suppliers cannot withdraw, borrowers cannot repay, liquidators cannot liquidate, and bad debt cannot be cleaned for that (hub, asset) book. All pool cash backing the book is stranded in the contract — a "contract unable to operate from lack of token funds" / permanent-freeze impact, the same severity class as the Moloch system halt.

### Likelihood Explanation
Reaching the cliff needs (a) a spoke cap at or near `max_cap_for_decimals` — a permitted configuration, not a validation bypass — and (b) a book large enough that `scaled * index` crosses `i128::MAX`. For an 18-decimal token at ~98% utilization on a steep curve, the harness shows this happens after single-digit years of compounding; a high-supply token (billions of whole units, plausible for memecoin-style assets) makes the capital requirement realistic. `update_indexes` is permissionless, so any user advances accrual; no privileged call is needed after listing. The main mitigants are time and the market-cap realism of the asset, keeping likelihood moderate rather than high.

### Recommendation
Make accrual saturation-safe instead of panicking:
- Clamp `scaled_to_original` results used for utilization at a defined ceiling (saturating `mul_div` already exists as `mul_div_floor_saturating`), or
- Cap the index before multiplying values: compute `new_borrow_index` first and short-circuit accrual when the stored index is at `MAX_BORROW_INDEX_RAY` (the docs already state "at the cap no further interest accrues"), and similarly check a *value* ceiling on `borrowed`/`supplied` so the unscale can't overflow, or
- Enforce tighter supply/borrow caps at listing so `scaled * MAX_INDEX` provably fits `i128` (i.e. validate `cap * 10^(27-d) * MAX_BORROW_INDEX_RAY / RAY <= i128::MAX`), closing the gap between `max_cap_for_decimals` and the actual accrual-safe bound. The documented bound in `docs/reference/formulas.md` should also be corrected — the test notes it is currently wrong.

### Proof of Concept
The repository contains the PoC verbatim: `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:320-361`.

```rust
// A billion 18-decimal whole tokens supplied, 98% borrowed, caps at the
// domain maximum (a permitted configuration via require_cap_within_asset_domain).
let principal = BILLION * 10i128.pow(18);
t.supply_raw(BOB, "BIG18", principal);
t.borrow_raw(ALICE, "BIG18", principal / 100 * 98);

// Accrue year by year via the permissionless update_indexes until MathOverflow.
loop { t.advance_time(YEAR_SECS); if let Err(e) = t.try_update_indexes_for(&["BIG18"]) { break e; } }
assert_contract_error(failed, errors::MATH_OVERFLOW);
assert!(book.borrow_index < MAX_BORROW_INDEX_RAY); // cap never engaged

// Market permanently frozen: every verb accrues first.
assert_contract_error(t.try_withdraw_raw(BOB, "BIG18", 1), errors::MATH_OVERFLOW);
assert_contract_error(t.try_repay(ALICE, "BIG18", 1.0), errors::MATH_OVERFLOW);
```

Caveat: this freeze is already documented by the project as "the one cliff the domain has" in the test file header — it is a real, unprivately reachable permanent freeze under permitted cap configuration, but whether it is treated as an accepted domain limitation should be confirmed against the audit scope.