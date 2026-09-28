### Title
Permanent market freeze: RAY-scaled debt value overflows `i128` during accrual before the borrow-index cap can engage - (File: common/src/rates/index.rs)

### Summary
The borrow index is capped at `MAX_BORROW_INDEX_RAY` in `update_borrow_index`, but the accrual path in `calculate_supplier_rewards` multiplies the scaled borrowed amount by the new index first. For a sufficiently large market at sustained high utilization, `borrowed * new_borrow_index` exceeds `i128::MAX` while the index is still below the cap, so `Ray::mul` panics with `MathOverflow`. Because every pool verb accrues first, the panic permanently bricks the market: no repay, no withdraw, no liquidation, no `clean_bad_debt`.

### Finding Description
`update_borrow_index` computes `old_index.mul(interest_factor)` and only then compares against `MAX_BORROW_INDEX_RAY` [1](#0-0) . Immediately after, `calculate_supplier_rewards` computes `borrowed.mul(old_borrow_index)` and `borrowed.mul(new_borrow_index)` [2](#0-1) . `Ray::mul` uses checked `i128`/`I256` multiply-divide that panics with `GenericError::MathOverflow` when the result does not fit [3](#0-2) . The scaled `borrowed` is denominated in RAY (10^27) per base unit, so for an 18-decimal asset the value ceiling is hit at roughly `i128::MAX / RAY ≈ 1.7e11` whole tokens times the index multiplier — a ceiling reached well before `MAX_BORROW_INDEX_RAY` on large supplies.

`accrue_chunk` calls this unconditionally for every market on every state-changing call via `global_sync` [4](#0-3) , and `global_sync` runs at the top of every verb [5](#0-4) . The repository's own harness test demonstrates the end state: after the overflow, `withdraw`, `repay`, and `update_indexes` all revert with `MATH_OVERFLOW`, and `last.borrow_index < MAX_BORROW_INDEX_RAY`, proving the cap never engaged [6](#0-5) .

The WebKit memory-corruption analog maps onto unchecked-arithmetic state corruption: an attacker-shaped input (a huge scaled debt book) drives fixed-point state past its representable range, and the protocol has no graceful clamp — it traps forever instead of bounding the index or the scaled value.

### Impact Explanation
Permanent freezing of all user funds in the affected market. Suppliers cannot withdraw, borrowers cannot repay, liquidators cannot liquidate, and bad-debt cleanup cannot run, because every one of those entrypoints (`withdraw`, `repay`, `liquidate`, `clean_bad_debt`, `flash_*`, `update_indexes`) calls `global_sync` → `accrue_chunk` → `calculate_supplier_rewards` and hits the same `MathOverflow`. Interest continues to accrue conceptually, so there is no time-based recovery path; once `borrowed * index` crosses `i128::MAX` the market is bricked forever and all deposited tokens are locked in the pool.

### Likelihood Explanation
A single unprivileged address can create the precondition: supply a very large amount of a high-decimals token and borrow it to near-full utilization via `controller::supply`/`borrow`, then let time pass (`update_indexes` is permissionless and accrues in chunks). The required principal is large — on the order of 10^11+ whole units of an 18-decimal asset at ~98% utilization over multiple years — so this is either a whale-capital attack or a latent fatal condition for any market that organically grows large while borrow/supply caps are set high or disabled. Spoke caps and max-utilization checks gate how big the book can get , but caps are governance parameters; any cap above the `i128`/RAY ceiling leaves the freeze reachable, and the borrow-index cap that was intended to bound growth provably does not protect this multiplication.

### Recommendation
Bound the accrual arithmetic, not just the index:
- In `calculate_supplier_rewards`, compute total debt via `mul_div_floor_saturating` or clamp `new_borrow_index` to `min(computed_index, i128::MAX / borrowed)` so the cap engages before the value overflows.
- Alternatively enforce a protocol-level invariant `borrowed_scaled * MAX_BORROW_INDEX_RAY <= i128::MAX` by deriving market caps from decimals (extend `max_cap_for_decimals`-style limits) so the product can never reach the ceiling.
- Consider making `global_sync` degrade to capping the index rather than reverting, preserving liveness of exit verbs.

### Proof of Concept
The repo's own test is the PoC (`tests/test-harness/tests/controller/large_positions_and_long_horizons.rs`):

```rust
let principal = BILLION * 10i128.pow(18);
t.supply_raw(BOB, "BIG18", principal);           // huge 18-decimal supply
t.borrow_raw(ALICE, "BIG18", principal / 100 * 98); // 98% utilization
loop {
    t.advance_time(YEAR_SECS);
    if let Err(e) = t.try_update_indexes_for(&["BIG18"]) { break e; } // MATH_OVERFLOW
}
// market frozen:
t.try_withdraw_raw(BOB, "BIG18", 1)   // -> MATH_OVERFLOW
t.try_repay(ALICE, "BIG18", 1.0)      // -> MATH_OVERFLOW
// last.borrow_index < MAX_BORROW_INDEX_RAY: cap never engaged
```

An unprivileged attacker replays this through `controller::supply` (mints scaled supply), `controller::borrow` (builds the scaled debt book), then permissionless `controller::update_indexes` after time passes. Once `borrowed * borrow_index` crosses `i128::MAX` inside `calculate_supplier_rewards`, every subsequent call on that market reverts.

### Citations

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

**File:** common/src/rates/index.rs (L80-83)
```rust
    let old_total_debt = borrowed.mul(env, old_borrow_index);
    let new_total_debt = borrowed.mul(env, new_borrow_index);

    let accrued_interest = new_total_debt.checked_sub(env, old_total_debt);
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

**File:** contracts/pool/src/interest.rs (L39-53)
```rust
fn accrue_chunk(env: &Env, cache: &mut Cache, delta_ms: u64) {
    let step = accrue_step(
        env,
        cache.params(),
        cache.borrowed(),
        cache.supplied(),
        cache.borrow_index(),
        cache.supply_index(),
        delta_ms,
    );

    cache.set_borrow_index(step.borrow_index);
    cache.set_supply_index(step.supply_index);
    cache.accrue_revenue(step.revenue_shares);
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
