### Title
RAY-value overflow in interest accrual permanently freezes a large, high-utilization market - (File: common/src/rates/simulate.rs)

### Summary
The bug class from CVE-2021-39518 (unbounded write/read past a buffer) maps onto Soroban as unbounded fixed-point growth past the `i128` domain. In `accrue_step`, the very first operation computes `scaled_to_original(env, borrowed, borrow_index)` — a `mul_div` of two RAY-scaled values that panics with `GenericError::MathOverflow` when the unscaled debt value exceeds `i128::MAX` (≈1.7e11 whole tokens in RAY terms). `update_borrow_index` clamps the index at `MAX_BORROW_INDEX_RAY`, but the clamp engages only after the multiplication, and the debt value (`borrowed × borrow_index`) overflows before the index cap is ever reached on a whale-scale market. Since `interest::global_sync` runs `accrue_chunk` on every mutation path — supply, borrow, withdraw, repay, net_settle, seize_positions, flash paths, `update_indexes` — a single panic bricks the entire market. [1](#0-0) [2](#0-1) [3](#0-2) 

### Finding Description
`accrue_step` unscales the raw `borrowed` share total against the compounding `borrow_index` via `scaled_to_original` → `Ray::mul` → `fp_core` multiply-divide, which widens to `I256` and then converts back with `.to_i128().unwrap_or(panic)` (panicking variants) — the non-saturating `mul` used here traps on overflow. The borrow index is capped at `MAX_BORROW_INDEX_RAY = 10^36` (1000×), and the cap check in `update_borrow_index` happens after the index multiplication, but nothing bounds `borrowed × borrow_index` itself. The RAY domain ceiling for a debt value is `i128::MAX / RAY ≈ 1.7e11` whole tokens; a market whose borrowed book, valued at the accreting index, crosses that line causes the next accrual to panic. The protocol's own harness test `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` demonstrates this: an 18-decimal market with a billion-token book at ~98% utilization on the steep end of the XLM rate curve hits `MathOverflow` (error 33) while `borrow_index` is still far below `MAX_BORROW_INDEX_RAY`, and the test confirms `withdraw` and `repay` fail with the same panic because they accrue first. [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) 

### Impact Explanation
Permanent freezing of funds: once `borrowed × borrow_index` crosses `i128::MAX`, every controller-facing verb on that `(hub, token)` book — `supply`, `withdraw`, `borrow`, `repay`, `liquidate`/`seize_positions`, `clean_bad_debt`, `claim_revenue`, `recapitalize`, `update_indexes` — reverts inside `global_sync` before touching state. Suppliers cannot exit, borrowers cannot repay or be liquidated, and no governance/owner escape exists because the panic precedes all guards. All cash held against that market is locked forever; collateral in other markets locked against the frozen debt is effectively trapped as well.

### Likelihood Explanation
Requires a very large book (debt × index > ~1.7e38 RAY) and sustained high utilization so the index compounds fast enough — on the order of years at the steep curve segment. These are whale-scale parameters, so likelihood is low; but it is triggered purely by time plus ordinary permissionless market activity, needs no privileged call, and there is no recovery path once crossed. The accrual-first architecture makes the freeze total rather than partial. Severity: Medium (high impact, demanding preconditions).

### Recommendation
Bound the debt value, not just the index: inside `accrue_step` (or `update_borrow_index`), stop index growth once `scaled_to_original(borrowed, new_borrow_index)` would exceed a configured ceiling (e.g. `i128::MAX / SAFETY` in RAY), analogous to the existing `MAX_BORROW_INDEX_RAY` clamp — freezing interest accrual freezes nothing else, whereas a panic freezes everything. Alternatively, saturate `scaled_to_original` for the utilization/rate computation (the rate curve output is insensitive at the top of the domain) so accrual degrades gracefully instead of trapping. A pre-mortem fix in `accrue_step` also protects every downstream entrypoint uniformly since they all funnel through `global_sync`.

### Proof of Concept
```rust
// tests/test-harness/tests/controller/large_positions_and_long_horizons.rs
let mut t = LendingTest::new()
    .with_market(big("BIG18", 18, xlm_curve()))
    .with_market(col())
    .with_max_utilization_disabled_all_markets()
    .build();
lift_caps(&t, "BIG18", 18);
let principal = BILLION * 10i128.pow(18);
t.supply_raw(BOB, "BIG18", principal);
t.borrow_raw(ALICE, "BIG18", principal / 100 * 98);   // ~98% utilization
// Advance ledger time; each year the permissionless accrual compounds
// borrow_index until borrowed * borrow_index overflows i128.
loop {
    t.advance_time(YEAR_SECS);
    if t.try_update_indexes_for(&["BIG18"]).is_err() { break; }
}
// Asserted in-repo: MathOverflow (33) on accrual, and the same panic on
// try_withdraw_raw / try_repay — the market is frozen below the index cap.
```

### Citations

**File:** common/src/rates/simulate.rs (L60-62)
```rust
    let borrowed_original = scaled_to_original(env, borrowed, borrow_index);
    let supplied_original = scaled_to_original(env, supplied, supply_index);
    let util = utilization(env, borrowed_original, supplied_original);
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

**File:** contracts/pool/README.md (L151-155)
```markdown
Every market entrypoint also panics with `PoolNotInitialized` (30) when the
market does not exist, and with `MathOverflow` (33) on a checked-arithmetic
overflow. `InternalError` (34) marks a broken invariant: `revenue > supplied`
after a supply burn or a deposit seizure, or a revenue claim that burns zero
shares.
```

**File:** contracts/pool/README.md (L158-167)
```markdown

Each mutation of an existing market runs this sequence:

```text
entrypoint (#[only_owner])
  → Cache::load             # read params + state, bump TTL
  → interest::global_sync   # accrue to now, in ≤1yr chunks
  → mutate                  # cache/shares.rs, cache/cash.rs
  → guards::*               # reserve, utilization, backing checks
  → commit → transfer_out → emit
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

**File:** common/src/rates/scaling.rs (L14-16)
```rust
pub fn scaled_to_original(env: &Env, scaled: Ray, index: Ray) -> Ray {
    scaled.mul(env, index)
}
```

**File:** common/src/math/fp_core.rs (L180-201)
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
}
```
