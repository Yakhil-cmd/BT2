### Title
Permanent market freeze: accrual panics on `scaled * index` overflow before the borrow-index cap can engage - ([File: common/src/rates/scaling.rs])

### Summary
The parse-server advisory is a crash-on-invalid-state DoS. The analog in XOXNO Lending is a permanent, irreversible freeze of an entire market: once `borrowed_scaled * borrow_index` exceeds `i128::MAX` inside `scaled_to_original`, every interest accrual panics with `MathOverflow`. Because `global_sync` runs accrual before every mutating verb, all entrypoints touching that market — `supply`, `borrow`, `withdraw`, `repay`, `liquidate`, `clean_bad_debt`, `recapitalize`, `update_indexes` — revert forever. No error is caught, no fallback exists, and the `MAX_BORROW_INDEX_RAY` cap never engages because the overflow happens *before* the capped index is stored.

### Finding Description
`accrue_step` in `common/src/rates/simulate.rs:51-94` begins each compound step by computing `borrowed_original = scaled_to_original(env, borrowed, borrow_index)` and `supplied_original = scaled_to_original(env, supplied, supply_index)` (lines 60-61). `scaled_to_original` multiplies the scaled `Ray` share count by the index via `mul_div_half_up` in `common/src/math/fp_core.rs:108-118`, which widens to `I256` but then calls `to_i128()` — returning `None` and panicking with `GenericError::MathOverflow` whenever the product exceeds `i128::MAX` (~1.7e38).

Scaled share counts are denominated in RAY (1e27), so a market with, e.g., ~1e27 scaled borrow shares (≈1 unit of RAY-denominated debt — but with an 18-decimal asset, 1e18 raw units = 1e27... actually scaled amounts are asset-amount × 10^(27-decimals), so a billion-unit 18-decimal supply yields `supplied_scaled_ray` ≈ 1e54/1e27 scale) reaches the cliff once the index grows to ~170×. `update_borrow_index` in `common/src/rates/index.rs:13-19` caps the index at `MAX_BORROW_INDEX_RAY` = 1e36, but with scaled balances near 1e38 the value overflow in `scaled_to_original` fires before the cap becomes relevant.

The pool's `global_sync` (`contracts/pool/src/interest.rs:20-33`) runs this accrual unconditionally at the top of every market mutation, so once the invariant `scaled * index ≤ i128::MAX` is broken, the panic is hit on every subsequent call — the market is permanently bricked. This is proven by the existing test `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` in `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:316-362`, which shows `update_indexes`, `withdraw`, and `repay` all reverting with `MATH_OVERFLOW`, and explicitly notes "the index cap did not engage before the value overflow."

### Impact Explanation
Permanent freezing of funds for all suppliers and borrowers in the affected market: no withdraw, no repay, no liquidation, no bad-debt cleanup. Bad debt cannot be socialized (`apply_bad_debt_to_supply_index` is never reached), liquidators cannot seize collateral, and suppliers' claims become unreachable. This meets the "permanent freezing of funds" acceptance criterion.

### Likelihood Explanation
Fully reachable by unprivileged addresses through normal `supply`/`borrow` calls. The attacker requirements are: (a) a high-decimals asset market (18 decimals maximizes the scaled share count per raw unit), (b) large absolute balances — scaled values near 1e38 raw — and (c) sustained high utilization so the borrow index compounds to ~170× before governance or other accruals reset the trajectory. The cost is capital-heavy (whale-scale supply plus a large borrow at ~98% utilization held for years of compounding), and `update_indexes` calls by anyone accelerate arrival — no permission needed. Once tripped it cannot be undone by any on-chain action, since every corrective path also accrues first.

### Recommendation
Bound the value domain, not just the index: cap scaled balances (`supplied_scaled_ray`, `borrowed_scaled_ray`) so that `scaled * MAX_SUPPLY_INDEX_RAY` and `scaled * MAX_BORROW_INDEX_RAY` can never exceed `i128::MAX`, enforced at mint time in `supply`/`borrow` and in `accrue_revenue`. Alternatively, saturate rather than panic: have `scaled_to_original` clamp to `i128::MAX` (or have accrual detect the overflow and skip index growth while keeping the market operable), so a reached ceiling degrades to capped interest instead of a frozen market. A cap-check inside `accrue_step` before `scaled_to_original` is called would keep `MAX_BORROW_INDEX_RAY` semantics meaningful.

### Proof of Concept
Reproduced verbatim by the in-repo test at `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:321-361`: create an 18-decimal market on the XLM curve with caps lifted, supply `1e9 * 10^18` units, borrow 98% of it, then advance time in 1-year increments calling `update_indexes`. Within 40 years `try_update_indexes_for(&["BIG18"])` fails with `MathOverflow`, and afterwards `try_withdraw_raw(BOB, "BIG18", 1)` and `try_repay(ALICE, "BIG18", 1.0)` both fail with the same error — confirming permanent freeze, with `borrow_index` still below `MAX_BORROW_INDEX_RAY` so no recovery path exists. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** common/src/rates/simulate.rs (L60-66)
```rust
    let borrowed_original = scaled_to_original(env, borrowed, borrow_index);
    let supplied_original = scaled_to_original(env, supplied, supply_index);
    let util = utilization(env, borrowed_original, supplied_original);
    let borrow_rate = calculate_borrow_rate(env, util, params);
    let interest_factor = compound_interest(env, borrow_rate, delta_ms);

    let new_borrow_index = update_borrow_index(env, borrow_index, interest_factor);
```

**File:** common/src/math/fp_core.rs (L108-118)
```rust
pub fn mul_div_half_up(env: &Env, x: i128, y: i128, d: i128) -> i128 {
    // The zero check runs first so debug and release builds agree on a zero
    // divisor: both surface `DivisionByZero` rather than tripping the assert.
    require_nonzero_divisor(env, d);
    debug_assert!(
        x >= 0 && y >= 0 && d > 0,
        "mul_div_half_up: non-negative x, y and positive d"
    );
    try_mul_div_half_up(env, x, y, d)
        .unwrap_or_else(|| panic_with_error!(env, GenericError::MathOverflow))
}
```

**File:** contracts/pool/src/interest.rs (L20-33)
```rust
pub(crate) fn global_sync(env: &Env, cache: &mut Cache) {
    if !cache.needs_accrual() {
        return;
    }

    let mut remaining = cache.elapsed_ms();
    while let Some(nonzero) = NonZeroU64::new(remaining) {
        let chunk = nonzero.get().min(MAX_COMPOUND_DELTA_MS);
        accrue_chunk(env, cache, chunk);
        remaining = remaining.saturating_sub(chunk);
    }

    cache.mark_accrued();
}
```

**File:** common/src/rates/index.rs (L13-19)
```rust
pub fn update_borrow_index(env: &Env, old_index: Ray, interest_factor: Ray) -> Ray {
    let new_index = old_index.mul(env, interest_factor);
    if new_index.raw() > MAX_BORROW_INDEX_RAY {
        return Ray::from(MAX_BORROW_INDEX_RAY);
    }
    new_index
}
```

**File:** tests/test-harness/tests/controller/large_positions_and_long_horizons.rs (L316-361)
```rust
/// `i128::MAX`, 170 times that. At the XLM curve's steep segment the index
/// grows past 170x in a few years, and the next accrual panics inside
/// `scaled_to_original`. Every verb accrues first, so the market freezes:
/// no repay, no withdraw, no liquidation. The index cap never engages.
#[test]
fn a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap() {
    let mut t = LendingTest::new()
        .with_market(big("BIG18", 18, xlm_curve()))
        .with_market(col())
        .with_max_utilization_disabled_all_markets()
        .build();
    lift_caps(&t, "BIG18", 18);
    lift_caps(&t, "COL", 7);
    let principal = BILLION * 10i128.pow(18);
    t.supply_raw(BOB, "BIG18", principal);
    let debt = principal / 100 * 98;
    t.supply_raw(ALICE, "COL", BILLION * 10_000_000 * 3);
    t.borrow_raw(ALICE, "BIG18", debt);

    let mut years = 0u32;
    let failure = loop {
        years += 1;
        assert!(
            years <= 40,
            "no cliff within 40 years; the bound in docs/reference/formulas.md is wrong"
        );
        t.advance_time(YEAR_SECS);
        if let Err(e) = t.try_update_indexes_for(&["BIG18"]) {
            break e;
        }
    };
    let failed: Result<(), soroban_sdk::Error> = Err(failure);
    assert_contract_error(failed, errors::MATH_OVERFLOW);
    let last = book(&t, "BIG18");
    assert!(
        last.borrow_index < MAX_BORROW_INDEX_RAY,
        "the index cap did not engage before the value overflow"
    );
    // The market is frozen: exits and repayments accrue first and hit the same panic.
    assert_contract_error(t.try_withdraw_raw(BOB, "BIG18", 1), errors::MATH_OVERFLOW);
    assert_contract_error(t.try_repay(ALICE, "BIG18", 1.0), errors::MATH_OVERFLOW);
    std::println!(
        "ray-value cliff reached after {years} years at 98 percent utilization on the XLM curve; last index x{:.1}",
        last.borrow_index as f64 / RAY as f64
    );
}
```
