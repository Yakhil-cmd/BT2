### Title
Accrual-time debt-value overflow panics before the borrow-index cap, permanently freezing a market - (File: common/src/rates/simulate.rs)

### Summary
CVE-2016-5357 is a numeric-processing bug: mishandled unsigned-integer arithmetic crashes the parser (denial of service). The analog in XOXNO Lending is an i128 overflow in interest accrual: `accrue_step` computes accrued debt value in the RAY domain and that product can exceed `i128::MAX` *before* `borrow_index` reaches its `MAX_BORROW_INDEX_RAY` (10^36) cap. Because every mutating verb accrues first (`global_sync`), once the market crosses that value ceiling every `supply`, `borrow`, `withdraw`, `repay`, `liquidate`, `clean_bad_debt`, `flash_loan`, `recapitalize` and the permissionless `update_indexes` itself panics with `MathOverflow` — forever, since accrual is monotone in time and the index never decreases. [1](#0-0) [2](#0-1) 

### Finding Description
`simulate_update_indexes_body`/`global_sync` chunk elapsed time and call `accrue_step`, which computes `interest = half_up(borrowed × borrow_index' / RAY) − half_up(borrowed × borrow_index / RAY)` and analogous scaled products. [3](#0-2)  The borrow index is capped at `10^36` RAY (`MAX_BORROW_INDEX_RAY`), so *index* growth is bounded — but the *value* `borrowed_scaled × index` is not. With a very large `borrowed` scaled total, the product `borrowed × borrow_index'` overflows `i128` while `borrow_index` is still well below its cap. The cap is applied to the index *after* the multiply, so it never engages; the multiplication traps inside the fixed-point engine (`mul_div_*` / `scaled_to_original`) with `MathOverflow`. [4](#0-3) 

The docs acknowledge the cliff ("Value overflow can occur before the index ceiling and block repayment/withdrawal"), but the defect is that nothing bounds or saturates the intermediate product — a single arithmetic overflow converts a bounded-index design into a permanently frozen market, which is exactly the crash-primitive shape of the CVE. [5](#0-4) 

### Impact Explanation
Permanent freezing of funds. Once the market's `borrowed × borrow_index` crosses the i128 ceiling:
- Suppliers cannot `withdraw` — every withdrawal accrues first and panics.
- Borrowers cannot `repay` — same first-accrue panic.
- Liquidators cannot `liquidate` — the plan path calls `cached_market_index`, which runs the same `accrue_step` and panics, so even underwater positions cannot be closed or their bad debt cleaned.
- `update_indexes` itself is permissionless and also panics, so no keeper can roll the market forward.

All user deposits and outstanding debt in that hub/token book are locked indefinitely; the only recovery is an upgrade/migration. The test `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` demonstrates the freeze end-to-end: after the accrual panic, `try_withdraw` and `try_repay` both revert with `MATH_OVERFLOW` while `borrow_index < MAX_BORROW_INDEX_RAY`. [6](#0-5) 

### Likelihood Explanation
Medium, matching the CVE's 5.9 (high complexity, high impact). Reaching the ceiling requires an extreme but fully permissionless state: roughly ≥170 billion whole-token equivalents of scaled debt at sustained ~98% utilization on a high-APR curve for multiple years (the test reaches it in under 40 simulated years on the XLM curve). Every step — `supply` the liquidity, `borrow` to high utilization, `update_indexes` to accrue — is callable by an unprivileged address, and `max_cap_for_decimals`-scale caps admit the required sizes when caps are lifted or set high. No privileged action, oracle manipulation, or timing luck is required beyond capital and time; once crossed, the freeze is irreversible because accrual is monotone and unconditional.

### Recommendation
Cap the accrual so the *value* domain cannot overflow before the index cap: inside `accrue_step`, compute the interest in wide (U256) arithmetic or clamp `borrow_index'` to the largest value for which `borrowed × borrow_index'` fits `i128` (i.e. `min(index_cap, i128::MAX / borrowed × RAY)` style bound), so accrual saturates at the representable ceiling instead of trapping. Alternatively, use `mul_div_floor_saturating` for the `borrowed × index` products so a saturated market accrues zero marginal interest rather than panicking — preserving the documented "at the ceiling, further accrual produces no borrower interest" behavior for value overflow as well. [7](#0-6) [8](#0-7) 

### Proof of Concept
A unprivileged sequence reproduces it (mirroring the existing harness test):

```rust
let mut t = LendingTest::new()
    .with_market(big("BIG18", 18, xlm_curve()))
    .with_market(col())
    .with_max_utilization_disabled_all_markets()
    .build();
lift_caps(&t, "BIG18", 18);
lift_caps(&t, "COL", 7);

let principal = BILLION * 10i128.pow(18);
t.supply_raw(BOB, "BIG18", principal);              // permissionless supply
t.supply_raw(ALICE, "COL", BILLION * 10_000_000 * 3);
t.borrow_raw(ALICE, "BIG18", principal / 100 * 98); // ~98% utilization

loop {
    t.advance_time(YEAR_SECS);
    if t.try_update_indexes_for(&["BIG18"]).is_err() { break; }
}
// Now the market is permanently frozen:
assert_contract_error(t.try_withdraw_raw(BOB, "BIG18", 1), errors::MATH_OVERFLOW);
assert_contract_error(t.try_repay(ALICE, "BIG18", 1.0), errors::MATH_OVERFLOW);
// borrow_index < MAX_BORROW_INDEX_RAY: the index cap never engaged.
```

Root cause: `accrue_step` multiplies `borrowed_scaled` by the new borrow index in i128/RAY arithmetic; the product overflows at roughly `i128::MAX` (~1.7e38) while `borrow_index` is still below `10^36` whenever `borrowed_scaled > ~1.7e29` scaled units — so the index bound cannot prevent the panic, and because accrual precedes every verb and is time-monotone, the panic is permanent. [9](#0-8) [10](#0-9)

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

**File:** common/src/rates/simulate.rs (L157-175)
```rust
    let mut remaining = total_delta_ms;
    while remaining > 0 {
        let chunk = remaining.min(MAX_COMPOUND_DELTA_MS);
        let step = accrue_step(
            env,
            &params,
            state.borrowed,
            supplied,
            borrow_index,
            supply_index,
            chunk,
        );

        borrow_index = step.borrow_index;
        supply_index = step.supply_index;
        supplied = supplied.checked_add(env, step.revenue_shares);

        remaining -= chunk;
    }
```

**File:** docs/reference/invariants.md (L229-237)
```markdown
### INV-IDX-01 — Borrow index is monotone and bounded

Both indexes start at one RAY. Successful accrual with validated rate parameters
cannot lower the borrow index and caps it at the protocol constant 10^36 raw
RAY. At the ceiling, further accrual produces no borrower interest.

Debt-value overflow can still revert accrual before that ceiling is reached.
Bounded indexes do not guarantee representable position or market values.

```

**File:** common/src/math/fp_core.rs (L180-200)
```rust
pub fn mul_div_floor_saturating(env: &Env, x: i128, y: i128, d: i128) -> i128 {
    require_nonzero_divisor(env, d);
    if let Some(quotient) = x
        .checked_mul(y)
        .and_then(|product| div_floor_i128(product, d))
    {
        return quotient;
    }
    let (x256, y256, d256) = to_i256_operands(env, x, y, d);
    div_floor_i256(
        env,
        &x256.mul(&y256),
        &d256,
        quotient_is_nonnegative(x, y, d),
    )
    .to_i128()
    .unwrap_or(if quotient_is_negative(x, y, d) {
        i128::MIN
    } else {
        i128::MAX
    })
```
