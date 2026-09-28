### Title
Oversized book makes every accrual panic: `scaled * index` overflows `i128` and permanently freezes the market - (File: common/src/rates/scaling.rs)

### Summary
tcprewrite's "large frame" crash maps here to a large *position/book* frame: once a market's scaled share total times its index exceeds `i128::MAX` in RAY terms, the interest-accrual step panics with `MathOverflow`. Since every state-changing entrypoint on both the pool and the controller accrues first, the market becomes permanently unrecoverable — no withdraw, repay, liquidate, or `update_indexes` ever succeeds again.

### Finding Description
Accrual runs through `global_sync` → `accrue_chunk` → `accrue_step`, which computes utilization and supplier revenue by unscaling the scaled book: `scaled_to_original(scaled, index)` is `scaled.mul(env, index)`, i.e. `mul_div_half_up(scaled_ray, index_ray, RAY)` [1](#0-0) . `mul_div_half_up` widens to `I256` but still returns `None`/panics when the *result* doesn't fit `i128` [2](#0-1) . `calculate_utilization` performs the same `scaled * index` product on both the borrowed and supplied books [3](#0-2) .

The supply-side cap check (`calculate_scaled_cap`) deliberately saturates instead of panicking, so an oversized book is only rejected if the *cap* is exceeded — nothing bounds `scaled * index` itself [4](#0-3) . `MAX_BORROW_INDEX_RAY` caps the index, but the value ceiling `scaled_ray * index_ray / RAY ≤ i128::MAX` is hit long before the index cap on a whale-scale book, so the guard never engages.

The project's own stress test demonstrates the cliff end-to-end: after ~170x index growth on a billion-unit 18-decimal market at 98% utilization, `update_indexes` fails with `MATH_OVERFLOW`, and subsequently `withdraw(1)` and `repay` both fail identically because they accrue first [5](#0-4) .

### Impact Explanation
Permanent freezing of funds: every supplier's deposit and every borrower's collateral/debt in that market is locked forever — `supply`, `withdraw`, `borrow`, `repay`, `liquidate`, `clean_bad_debt`, `claim_revenue`, `recapitalize`, and `update_indexes` all call `global_sync` first and all revert on the same `MathOverflow` [6](#0-5) . There is no recovery path: the panic is in the accrual math itself, not in a per-verb check, and `apply_bad_debt_to_supply_index`/`recapitalize` cannot shrink the scaled book without touching user shares.

### Likelihood Explanation
Reachable only through normal unprivileged verbs (`supply`, `borrow`), but it requires a genuinely enormous book — RAY-value of supply or debt exceeding ~1.7e11 whole-token equivalents — plus sustained high utilization for the index to multiply the scaled book past the cliff (the test needs ~years at 98% on a 175% max-rate curve). Low-cost variants (direct large `supply` near the cap, 18-decimal assets with lifted caps) shorten the runway but still demand whale capital and time. Medium severity: deterministic permanent freeze once reached, but a high capital/time bar and no direct profit to the attacker (griefing/accidental).

### Recommendation
Add a domain guard at booking time, not just at the cap check: when `calculate_scaled_supply`/`calculate_scaled_borrow` grow the book, verify `scaled_total * index_ceiling` stays inside `i128` (e.g. compute `scaled_to_original(scaled_total, MAX_BORROW_INDEX_RAY)` with the saturating variant and reject if it saturates). Alternatively, on accrual, clamp the index per chunk so `scaled * index` remains representable, or store utilization inputs pre-multiplied so accrual never needs the overflowing product. A documented cap on per-market RAY value (e.g. `max_cap_for_decimals` tightened by a factor of `MAX_BORROW_INDEX_RAY`) removes the cliff entirely.

### Proof of Concept
1. `supply(whale, BIG18, 1_000_000_000e18)` — succeeds (cap lifted/`require_cap_within_asset_domain` passes).
2. `borrow(victim, BIG18, ~0.98 * supply)` — utilization pinned near the steep curve segment.
3. Advance ledger time in `MAX_COMPOUND_DELTA_MS` chunks via any verb; `global_sync` compounds `borrow_index` upward each call [7](#0-6) .
4. Once `borrowed_scaled_ray * borrow_index / RAY > i128::MAX`, the next `accrue_step` panics inside `scaled_to_original` with `GenericError::MathOverflow` [1](#0-0) .
5. `try_update_indexes`, `withdraw(BOB, BIG18, 1)`, `repay(ALICE, BIG18, …)` all revert with `MATH_OVERFLOW` — confirmed by `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` [8](#0-7) . The market is frozen permanently.

### Citations

**File:** common/src/rates/scaling.rs (L14-16)
```rust
pub fn scaled_to_original(env: &Env, scaled: Ray, index: Ray) -> Ray {
    scaled.mul(env, index)
}
```

**File:** common/src/rates/scaling.rs (L26-33)
```rust
pub fn calculate_scaled_cap(env: &Env, cap: i128, decimals: u32, index: Ray) -> Ray {
    Ray::from(fp_core::mul_div_floor_saturating(
        env,
        Ray::from_asset(env, cap, decimals).raw(),
        RAY,
        index.raw(),
    ))
}
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

**File:** contracts/pool/src/cache/scale.rs (L19-27)
```rust
    pub(crate) fn calculate_utilization(&self) -> Ray {
        if self.supplied == Ray::ZERO {
            return Ray::ZERO;
        }
        let total_borrowed = scaled_to_original(&self.env, self.borrowed, self.borrow_index);
        let total_supplied = scaled_to_original(&self.env, self.supplied, self.supply_index);

        utilization(&self.env, total_borrowed, total_supplied)
    }
```

**File:** tests/test-harness/tests/controller/large_positions_and_long_horizons.rs (L316-360)
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
