### Title
RAY-scaled debt valuation overflows `i128` during accrual before the borrow-index cap can engage, permanently freezing the market - ([File: common/src/rates/simulate.rs])

### Summary
The external report's bug class — unchecked arithmetic that can overflow — maps onto XOXNO Lending's RAY-scaled share accounting. All value math is `i128` with an exact `I256` fast/wide path, but several accrual steps do **not** use the wide path: they call `Ray::mul` directly on two RAY-scaled quantities. When `borrowed × borrow_index` exceeds `i128::MAX`, `accrue_step` panics with `MathOverflow`. Because `global_sync` runs before every pool verb, once that boundary is crossed the whole market is permanently bricked — and the existing borrow-index ceiling at `10^36` does not prevent it, because the product overflows long before the index reaches the cap.

### Finding Description
`accrue_step` in `common/src/rates/simulate.rs:60` computes `scaled_to_original(env, borrowed, borrow_index)`, which is a plain `scaled.mul(env, index)` in `common/src/rates/scaling.rs:14-16`. `Ray::mul` panics when `borrowed * index / RAY` doesn't fit `i128`. The same step then calls `calculate_supplier_rewards` in `common/src/rates/index.rs:80-83`, which evaluates `borrowed.mul(env, new_borrow_index)` — again a raw RAY×RAY multiply. [1](#0-0) [2](#0-1) [3](#0-2) 

The borrow index is capped at `MAX_BORROW_INDEX_RAY = 10^36` by `update_borrow_index` (`common/src/rates/index.rs:13-19`, `common/src/constants/pool.rs:19`), but the cap is applied to the index *value*, not to the `borrowed × index` *product*. With borrowed shares on the order of `~10^30` (a whale-scale, high-decimal market), the product overflows at an index around 170 RAY — far below `10^36` — so the ceiling never engages before the panic. [4](#0-3) [5](#0-4) 

Every state-changing entrypoint accrues first: `global_sync` (`contracts/pool/src/interest.rs:20-33`) runs `accrue_step` per chunk before `supply`, `withdraw`, `borrow`, `repay`, `update_indexes`, and the controller-driven `liquidate`/`clean_bad_debt` pool ops. The codebase's own test harness demonstrates the result: `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` advances time on a 98%-utilization whale market until `try_update_indexes_for` fails with `MATH_OVERFLOW`, then asserts `withdraw` and `repay` also revert and that the index cap never engaged (`tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:320-360`). [6](#0-5) [7](#0-6) 

### Impact Explanation
Permanent freezing of funds. Once `borrowed × borrow_index` crosses the `i128` boundary, every subsequent call panics inside accrual: suppliers cannot `withdraw`, borrowers cannot `repay`, liquidators cannot seize, `update_indexes` cannot checkpoint, and `clean_bad_debt`/`recapitalize` paths that touch the cache accrue first. No privileged or unprivileged recovery path exists — the `update_borrow_index` cap that was supposed to bound growth is unreachable because the multiply overflows first. All supplied liquidity in that market's spoke book is frozen forever.

### Likelihood Explanation
Medium. Triggering requires (a) a market where scaled debt `borrowed` is large enough that `borrowed × ~170·RAY ≥ i128::MAX` — roughly a billion-scale supply of a high-decimals asset — and (b) sustained high utilization so the index compounds to that point over multiple years. An unprivileged address can drive both legs: supply the whale position, `borrow` to push utilization into the steep segment of the rate curve, and simply not repay while calling `update_indexes` (a permissionless entrypoint) periodically to keep accrual progressing. The exploit needs no privileged access, no oracle manipulation, and no cooperation — only capital and time — but the capital scale and multi-year horizon make it less than trivially reachable.

### Recommendation
Use the widening `I256` path for debt/supply valuation inside accrual rather than raw `Ray::mul`:

- In `common/src/rates/scaling.rs::scaled_to_original` (and its uses inside `accrue_step`), compute `borrowed * index / RAY` through `fp_core::mul_div_half_up`, which already widens to `I256` when the intermediate product doesn't fit `i128`, or detect overflow and clamp/saturate the *valuation* rather than trap.
- Apply the same treatment to `calculate_supplier_rewards` (`common/src/rates/index.rs:80-83`): the delta between old and new total debt fits `i128` even when each absolute total doesn't, so compute it as `borrowed * (new_index − old_index) / RAY` (which cannot overflow since `new_index − old_index` is bounded) instead of subtracting two overflowing products.
- Alternatively, enforce a ceiling on `borrowed × index` (a market-level debt-value cap checked at borrow time) so the product can never approach `i128::MAX`, making the panic unreachable by construction.

### Proof of Concept
The repo already contains the working demonstration:

```text
// tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:320-360
let principal = BILLION * 10i128.pow(18);          // 1e9 tokens, 18 decimals
t.supply_raw(BOB, "BIG18", principal);             // unprivileged supply
let debt = principal / 100 * 98;                   // 98% utilization
t.supply_raw(ALICE, "COL", BILLION * 10_000_000 * 3);
t.borrow_raw(ALICE, "BIG18", debt);                // unprivileged borrow

loop {
    t.advance_time(YEAR_SECS);
    if let Err(e) = t.try_update_indexes_for(&["BIG18"]) { break e; }  // anyone can call update_indexes
}
assert_contract_error(failed, errors::MATH_OVERFLOW);
assert!(last.borrow_index < MAX_BORROW_INDEX_RAY);  // cap never engaged
assert_contract_error(t.try_withdraw_raw(BOB, "BIG18", 1), errors::MATH_OVERFLOW); // frozen
assert_contract_error(t.try_repay(ALICE, "BIG18", 1.0), errors::MATH_OVERFLOW);    // frozen
```

Unprivileged attack path: `supply` a whale-scale position on a high-decimals market → `borrow` to ~98% utilization → let interest compound (anyone may call `update_indexes`) → `accrue_step` panics at `scaled_to_original(borrowed, borrow_index)` → `withdraw`/`repay`/`liquidate`/`update_indexes` all revert permanently.

### Citations

**File:** common/src/rates/simulate.rs (L60-69)
```rust
    let borrowed_original = scaled_to_original(env, borrowed, borrow_index);
    let supplied_original = scaled_to_original(env, supplied, supply_index);
    let util = utilization(env, borrowed_original, supplied_original);
    let borrow_rate = calculate_borrow_rate(env, util, params);
    let interest_factor = compound_interest(env, borrow_rate, delta_ms);

    let new_borrow_index = update_borrow_index(env, borrow_index, interest_factor);

    let (supplier_rewards, protocol_fee) =
        calculate_supplier_rewards(env, params, borrowed, new_borrow_index, borrow_index);
```

**File:** common/src/rates/scaling.rs (L14-16)
```rust
pub fn scaled_to_original(env: &Env, scaled: Ray, index: Ray) -> Ray {
    scaled.mul(env, index)
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

**File:** common/src/rates/index.rs (L80-83)
```rust
    let old_total_debt = borrowed.mul(env, old_borrow_index);
    let new_total_debt = borrowed.mul(env, new_borrow_index);

    let accrued_interest = new_total_debt.checked_sub(env, old_total_debt);
```

**File:** common/src/constants/pool.rs (L18-23)
```rust
/// Ceiling the borrow index is clamped to after growth, in raw ray units.
pub const MAX_BORROW_INDEX_RAY: i128 = 1_000_000_000_000_000_000_000_000_000_000_000_000;

/// Ceiling the supply index is clamped to after growth, in raw ray units.
/// Equal to [`MAX_BORROW_INDEX_RAY`].
pub const MAX_SUPPLY_INDEX_RAY: i128 = MAX_BORROW_INDEX_RAY;
```

**File:** contracts/pool/src/interest.rs (L20-53)
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

/// Applies one compound step of `delta_ms` to indexes and protocol revenue.
///
/// The arithmetic lives in [`accrue_step`], shared with the read-only
/// `simulate_update_indexes` so the view and the mutator cannot drift.
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
