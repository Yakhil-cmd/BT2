### Title
RAY-valued position totals overflow `i128` inside accrual, permanently freezing all market operations - (File: common/src/rates/scaling.rs)

### Summary
XOXNO Lending scales supply and debt positions by RAY indexes and unscales them via `scaled_to_original` (`scaled.mul(env, index)`), which panics with `MathOverflow` when the product exceeds `i128`. Because every mutating pool verb runs `interest::global_sync` first — and `accrue_step` computes `scaled_to_original(borrowed, borrow_index)` and `scaled_to_original(supplied, supply_index)` before updating indexes — a whale-sized market at sustained high utilization crosses the RAY-value ceiling long before the `MAX_BORROW_INDEX_RAY` index cap engages. From that point every entrypoint that touches the market reverts, permanently: no repay, no withdraw, no liquidation, no bad-debt cleanup. The protocol's own test `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` demonstrates exactly this: after the cliff, `try_update_indexes_for`, `try_withdraw_raw`, and `try_repay` all fail with `MATH_OVERFLOW`, while `borrow_index < MAX_BORROW_INDEX_RAY` proves the cap never caught it.

### Finding Description
The bug class from the external report — large `uint256`/`i128` quantities combined in arithmetic that overflows the machine word — maps onto XOXNO's share accounting in `common/src/rates/scaling.rs:14-16`, where `scaled_to_original` delegates to `Ray::mul` → `fp_core::mul_div_half_up`, which panics with `GenericError::MathOverflow` when `scaled * index` exceeds `i128` (`common/src/math/fp_core.rs:108-118`). The accrual step in `common/src/rates/simulate.rs` calls `scaled_to_original` on the market's total `borrowed` and `supplied` scaled shares each chunk to compute utilization; `contracts/pool/src/interest.rs::global_sync` runs this before any mutation, and the pool README confirms "Each mutation of an existing market runs ... `interest::global_sync` → mutate". `docs/reference/formulas.md` (numeric-limits section) explicitly admits the gap: "valid caps and bounded indexes do not guarantee that future accrual fits. Value overflow can occur before the index ceiling and block repayment/withdrawal because those operations accrue first." The token-to-RAY domain admits ~170 billion whole tokens (`i128::MAX / 10^(27-d)`), so a position scaled value near the admitted cap multiplied by a borrow index that has grown ~170x overflows — reachable in a few years at the steep end of a configured rate curve (test uses 175% max APR, 98% utilization).

### Impact Explanation
Permanent freezing of user funds: once the accrual path overflows, `update_indexes`, `withdraw`, `repay`, `liquidate`, `clean_bad_debt`, and `recapitalize` on that market all panic, since each accrues first. Suppliers cannot exit, borrowers cannot repay, liquidators cannot clear positions, and protocol revenue in that market is unclaimable. The freeze is self-reinforcing: more elapsed time only grows the index further.

### Likelihood Explanation
An unprivileged whale can reach it with only `supply` and `borrow`: supply near the cap of a high-decimal asset and borrow near max utilization, then let interest accrue unattended. The inputs required are within the admitted domain (`max_cap_for_decimals`), not malformed parameters, though it demands a very large notional position (billions of whole tokens) and sustained high utilization/years of accrual, making it a Medium rather than High. No index-ceiling alarm exists ("No dedicated ceiling alarm is emitted"), so the cliff arrives without warning.

### Recommendation
In `accrue_step`/`global_sync`, clamp or saturate the unscaled totals used for utilization (e.g., a `mul_div_floor_saturating` variant for the utilization numerator/denominator, as `calculate_scaled_cap` already does for caps at `scaling.rs:26-33`), so accrual can still land and pin the borrow index at `MAX_BORROW_INDEX_RAY` instead of trapping. Alternatively, enforce a scaled-position ceiling at mint time (`calculate_scaled_supply`/`calculate_scaled_borrow`) that guarantees `scaled * MAX_INDEX` stays in `i128`, or add an `update_indexes` path that accrues debt-side only when value unscaling overflows so repayment and liquidation remain possible.

### Proof of Concept
```rust
// Mirrors tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:321
let mut t = LendingTest::new()
    .with_market(big("BIG18", 18, xlm_curve())) // 175% max APR steep curve
    .with_market(col())
    .with_max_utilization_disabled_all_markets()
    .build();
lift_caps(&t, "BIG18", 18); // cap = max_cap_for_decimals(18), admitted max
lift_caps(&t, "COL", 7);
let principal = BILLION * 10i128.pow(18);
t.supply_raw(BOB, "BIG18", principal);           // whale supply, unprivileged
t.supply_raw(ALICE, "COL", BILLION * 10_000_000 * 3);
t.borrow_raw(ALICE, "BIG18", principal / 100 * 98); // 98% utilization

// Advance ~N years; at some point accrual panics inside scaled_to_original:
//   scaled_borrowed * borrow_index > i128::MAX  →  MathOverflow (33)
assert_contract_error(t.try_update_indexes_for(&["BIG18"]), errors::MATH_OVERFLOW);
// Market is permanently frozen — every verb accrues first:
assert_contract_error(t.try_withdraw_raw(BOB, "BIG18", 1), errors::MATH_OVERFLOW);
assert_contract_error(t.try_repay(ALICE, "BIG18", 1.0), errors::MATH_OVERFLOW);
// borrow_index < MAX_BORROW_INDEX_RAY: the index cap never engaged.
```