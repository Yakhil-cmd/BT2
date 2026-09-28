### Title
Permanent market freeze via i128 overflow in interest accrual before the borrow-index cap engages - ([File: common/src/rates/index.rs])

### Summary
Every state-changing pool operation calls `global_sync`, which compounds interest through `accrue_step`. Inside that step, `calculate_supplier_rewards` and `update_supply_index` compute `borrowed.mul(env, index)` / `supplied.mul(env, old_index)` — i.e., `mul_div_half_up`, which panics with `MathOverflow` when `scaled * index` does not fit `i128` even after the exact `I256` intermediate. The borrow index is capped at `MAX_BORROW_INDEX_RAY`, but the cap is applied to the index, not to the `scaled × index` product, so a sufficiently large market hits the RAY-value ceiling (`scaled × index > i128::MAX`) before the index cap ever engages. Because accrual runs first in every verb, the market is permanently frozen: no repay, withdraw, or liquidation can execute — a missing-overflow-guard analog of CVE-2017-9835's unchecked allocation-size multiplication.

### Finding Description
- `global_sync` chunks elapsed time and calls `accrue_chunk` → `accrue_step` for every accrual, at the head of supply/borrow/withdraw/repay/liquidate paths [1](#0-0) .
- `update_borrow_index` clamps `new_index` to `MAX_BORROW_INDEX_RAY`, but only *after* computing it [2](#0-1) .
- `calculate_supplier_rewards` then computes `borrowed.mul(env, new_borrow_index)` and `borrowed.mul(env, old_borrow_index)`; `Ray::mul` is `mul_div_half_up`, which panics with `GenericError::MathOverflow` when the product exceeds `i128` [3](#0-2) [4](#0-3) .
- `scaled_to_original` (same unguarded multiply) and `update_supply_index`'s `supplied.mul(env, old_index)` have the same exposure [5](#0-4) [6](#0-5) .
- The protocol's own harness test demonstrates the cliff: an 18-decimal market with ~1B-token principal at ~98% utilization on the XLM rate curve reaches `MathOverflow` inside accrual while `borrow_index < MAX_BORROW_INDEX_RAY`, after which `withdraw` and `repay` both revert with `MATH_OVERFLOW` permanently [7](#0-6) .

### Impact Explanation
Permanent freezing of all funds in the affected market — an accepted impact class. Once `borrowed × borrow_index` (or `supplied × supply_index`) crosses `i128::MAX`, `global_sync` panics on every subsequent call, and since accrual precedes every user verb, suppliers cannot withdraw, borrowers cannot repay, and liquidators cannot liquidate. The index cap designed to bound growth is unreachable because the value product overflows first.

### Likelihood Explanation
Requires an unusually large market (the PoC uses ~10^27 base units supplied at ~98% utilization) and multi-year sustained accrual, so it is not reachable cheaply by an arbitrary unprivileged address; it is a realistic tail risk for whale-scale high-decimal markets rather than a trivially triggered condition. No privileged role is needed — any actor can keep a market at high utilization simply by holding a borrow position.

### Recommendation
Make accrual overflow-safe rather than panicking: saturate the products in `calculate_supplier_rewards` / `update_supply_index` / `scaled_to_original` (e.g., a `mul_saturating` variant or `mul_div_floor_saturating`), or enforce the index caps *before* the value multiplication so `scaled × capped_index` provably fits `i128`. Alternatively, cap total scaled supply/borrow per market at listing or supply time to a bound derived from `i128::MAX / MAX_*_INDEX_RAY`, so the accrual invariant holds by construction.

### Proof of Concept
The repository's own test `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` in `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:321-360` supplies `BILLION * 10^18` units of an 18-decimal asset, borrows ~98% of it, advances time year-by-year, and observes `try_update_indexes_for`, `try_withdraw_raw`, and `try_repay` all failing with `MATH_OVERFLOW` while `borrow_index < MAX_BORROW_INDEX_RAY` — demonstrating a permanent, unrecoverable market freeze reachable through ordinary `supply`/`borrow` calls.

### Citations

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

**File:** common/src/rates/index.rs (L34-34)
```rust
    let total_supplied_value = supplied.mul(env, old_index);
```

**File:** common/src/rates/index.rs (L80-86)
```rust
    let old_total_debt = borrowed.mul(env, old_borrow_index);
    let new_total_debt = borrowed.mul(env, new_borrow_index);

    let accrued_interest = new_total_debt.checked_sub(env, old_total_debt);

    let protocol_fee = params.reserve_factor.apply_to_ray(env, accrued_interest);
    let supplier_rewards = accrued_interest.checked_sub(env, protocol_fee);
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

**File:** common/src/rates/scaling.rs (L14-16)
```rust
pub fn scaled_to_original(env: &Env, scaled: Ray, index: Ray) -> Ray {
    scaled.mul(env, index)
}
```

**File:** tests/test-harness/tests/controller/large_positions_and_long_horizons.rs (L316-356)
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
```
