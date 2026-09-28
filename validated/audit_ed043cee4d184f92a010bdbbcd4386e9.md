### Title
RAY-value overflow in debt un-scaling panics `update_indexes`, permanently freezing an entire market - (File: common/src/rates/scaling.rs)

### Summary
A whale with a large enough supply position in a high-decimal market can push the accrued RAY-scaled debt value (`scaled_shares * borrow_index`) past the `i128` ceiling before the borrow-index cap engages. `update_indexes` — which is permissionless and invoked first by `supply`, `withdraw`, `borrow`, `repay`, `liquidate`, `clean_bad_debt`, and every flash/strategy path — then panics with `GenericError::MathOverflow` inside `scaled_to_original`, bricking the market for all users: no withdrawal, no repayment, no liquidation.

### Finding Description
The CVE's bug class is an input-reachable abort inside a normalization routine that halts the whole engine. The analog in XOXNO is the share→token normalization `scaled_to_original` in `common/src/rates/scaling.rs:14-16`, which calls `Ray::mul` → `mul_div_half_up` → `panic_with_error!(MathOverflow)` on overflow in `common/src/math/fp_core.rs:108-118`. During accrual the pool un-scales `borrowed_shares * borrow_index` to revalue debt; the product is a RAY-domain value that must fit `i128`. Docs acknowledge this: "Value overflow can occur before the index ceiling and block repayment/withdrawal because those operations accrue first" (`docs/reference/formulas.md:435-437`) and "Finite RAY value capacity can be exhausted before the index ceiling... an overlarge book can then fail before an otherwise risk-reducing operation" (`docs/explanation/threat-model.md:319-321`). The cap→scaled conversion saturates rather than reverting (`common/src/rates/scaling.rs:26-33`), so governance caps do not prevent the attacker from admitting the large position — `calculate_scaled_cap` fails open, while position accounting (`calculate_scaled_supply`/`calculate_scaled_borrow`) only needs to fit at entry index. The maintenance test `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` in `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:321-361` demonstrates the exact reachable state: 1 billion whole 18-decimal tokens supplied, 98% borrowed, sustained accrual on the XLM curve — `try_update_indexes_for(["BIG18"])` reverts with `MATH_OVERFLOW` while `borrow_index < MAX_BORROW_INDEX_RAY`, and subsequent `try_withdraw_raw` and `try_repay` revert identically.

### Impact Explanation
Permanent freezing of funds (Medium/High class). Once the debt value overflows, `update_indexes` panics for every account touching the market, and since all mutating verbs accrue the market before acting, suppliers can never withdraw, borrowers can never repay, liquidators can never act, and bad-debt cleanup is also blocked because `clean_bad_debt` accrues first. The book is a write-only sink.

### Likelihood Explanation
A single unprivileged address needs only: (a) a listed borrowable market with high decimals (e.g., 18), (b) enough tokens to reach ~`i128::MAX`-scale RAY debt value — roughly 170 billion whole tokens maximum domain, reachable faster at a steep curve segment where the index multiplies the value, and (c) permissionless calls to `update_indexes` over time. No privileged role, oracle manipulation, or MEV is required; time and capital are the only inputs. The capital requirement is high, which is the main mitigator and supports Medium rather than Critical.

### Recommendation
Cap per-market scaled debt/supply share totals or token-unit exposure conservatively at entry so that `shares * MAX_BORROW_INDEX_RAY / RAY` (i.e., value at the 1e36 index ceiling) stays comfortably within `i128` — validate admitted caps against the index ceiling rather than the current index, instead of relying on the saturating `calculate_scaled_cap` admission check. Alternatively, make accrual degrade gracefully: on debt-value overflow, clamp the borrow index at `MAX_BORROW_INDEX_RAY` (as the ceiling path already does for further accrual) and proceed with the capped value, rather than panicking. Also emit an alarm when a book approaches the RAY value capacity, since "no dedicated ceiling alarm is emitted" today.

### Proof of Concept
Reproduced by the in-repo test at `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:321-361`:

```rust
// Attacker-supplied conditions (no privileges):
//  BIG18: 18-decimal market on the XLM rate curve
//  1e9 whole tokens supplied (BOB), 98% borrowed (ALICE)
t.supply_raw(BOB, "BIG18", BILLION * 10i128.pow(18));
t.borrow_raw(ALICE, "BIG18", debt /* 0.98 * principal */);

// Any user then calls the permissionless entrypoint over time:
//   controller.update_indexes(markets=[BIG18])
// After enough elapsed ledgers it reverts with MathOverflow inside
// scaled_to_original(borrowed_shares, borrow_index).
assert_contract_error(t.try_update_indexes_for(&["BIG18"]), errors::MATH_OVERFLOW);

// From this point the market is bricked — every verb accrues first:
assert_contract_error(t.try_withdraw_raw(BOB, "BIG18", 1), errors::MATH_OVERFLOW);
assert_contract_error(t.try_repay(ALICE, "BIG18", 1.0),    errors::MATH_OVERFLOW);
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** common/src/rates/scaling.rs (L12-16)
```rust
/// Converts a scaled `Ray` amount to its original (unscaled) value by
/// multiplying by `index`, rounding half up.
pub fn scaled_to_original(env: &Env, scaled: Ray, index: Ray) -> Ray {
    scaled.mul(env, index)
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

**File:** tests/test-harness/tests/controller/large_positions_and_long_horizons.rs (L315-361)
```rust
/// The cliff. A billion whole tokens is `1e36` raw ray; the value ceiling is
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

**File:** docs/reference/formulas.md (L433-437)
```markdown
values and market totals must independently fit the RAY domain; valid caps and
bounded indexes do not guarantee that future accrual fits. Value overflow can
occur before the index ceiling and block repayment/withdrawal because those
operations accrue first. At the borrow-index ceiling, further accrual produces
no borrower interest. No dedicated ceiling alarm is emitted.
```

**File:** docs/explanation/threat-model.md (L317-324)
```markdown
## Numeric and resource limits

Finite RAY value capacity can be exhausted before the index ceiling. Synchronizing
an overlarge book can then fail before an otherwise risk-reducing operation.
Caps must account for plausible index growth as well as token balances.
Accrual cadence changes utilization and subsequent rates; bounded chunks do not
make cadence neutral or prove exact conservation after integer rounding.
See [numeric limits](../reference/formulas.md#numeric-limits).
```
