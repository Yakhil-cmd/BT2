### Title
Debt-value i128 overflow in accrual permanently bricks a market — (File: common/src/rates/index.rs)

### Summary
The analog of CVE-2017-20005 (integer overflow triggered when an attacker-controlled quantity is combined with time) is the RAY-value cliff in XOXNO Lending's interest accrual: `calculate_supplier_rewards` computes `borrowed * borrow_index` in `i128`, and once total debt value exceeds `i128::MAX` the multiply panics. Because `global_sync` runs `accrue_step` before every pool mutation and the borrow index is monotone, the overflow is permanent — every entrypoint that touches the market (`supply`, `borrow`, `withdraw`, `repay`, `liquidate`, `clean_bad_debt`, `flash_loan`, `update_indexes`) reverts forever. The harness test `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` demonstrates the freeze end-to-end and asserts the `MAX_BORROW_INDEX_RAY` cap never engages first. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

### Finding Description
`accrue_step` (in `common/src/rates/simulate.rs`, invoked from `contracts/pool/src/interest.rs::global_sync` / `accrue_chunk`) calls `calculate_supplier_rewards`, which does `borrowed.mul(env, new_borrow_index)` and `borrowed.mul(env, old_borrow_index)` where `Ray::mul` panics with `GenericError::MathOverflow` on `i128` overflow. `borrowed` is the sum of all users' scaled debt shares and grows with supply/borrow caps up to `max_cap_for_decimals`; `borrow_index` compounds upward without bound relative to the value domain (the `MAX_BORROW_INDEX_RAY = 10^36` cap only stops index growth, not the value multiplication — and the test proves the value overflows before the cap is reached). Since `borrow_index` can never decrease, once `borrowed * borrow_index` overflows `i128`, it overflows on every subsequent call — the panic is deterministic and irreversible. Every controller verb routes through `ops::synced_market`/`accrue`, so the market cannot be unwound, repaid, liquidated, or exited. [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7) 

### Impact Explanation
Permanent freezing of all supplier and borrower funds in the affected (hub, token) market, plus protocol insolvency on the outstanding debt: suppliers cannot withdraw (`withdraw` accrues first and panics), borrowers cannot repay, liquidators cannot liquidate (HF can never be evaluated post-overflow since accrual precedes risk reads), and `clean_bad_debt`/`recapitalize` hit the same accrual panic, so the bad debt can never be written down or covered. The test asserts `try_withdraw_raw`, `try_repay`, and `try_update_indexes_for` all revert with `MATH_OVERFLOW`. [9](#0-8) 

### Likelihood Explanation
Reachable entirely by unprivileged addresses: an attacker supplies a large position in a high-decimals asset (caps can be set to `max_cap_for_decimals`), borrows near `max_utilization` (up to RAY, i.e. 100%), and waits. On a steep curve (the test uses the XLM stress curve, `max_borrow_rate` 175% — within the `MAX_BORROW_RATE_RAY = 2*RAY` bound), compounding at high utilization grows `borrow_index` ~170x within decades and the debt value crosses `i128::MAX`. Because debt compounds while nobody acts (the market drifts toward max utilization as debt grows faster than supply), the freeze arrives by pure time passage — no attacker action is needed at the cliff itself. The attacker's own borrowed funds are effectively unrecoverable too, but the cost is bounded: they borrowed against collateral and can abandon the position, while all other suppliers' funds are frozen permanently. Likelihood is Medium — it requires a large-cap, high-utilization market and multi-year compounding, but requires no privileged action and no oracle manipulation. [10](#0-9) [11](#0-10) 

### Recommendation
Perform the debt-value computation in `I256` (or `u256`) inside `calculate_supplier_rewards` and `scaled_to_original` — e.g. `I256::from_i128(env, borrowed.raw()).mul(&I256::from_i128(env, index.raw()))` — and saturate/clamp the result instead of panicking, so accrual can always proceed. Alternatively, gate accrual behind a debt-value ceiling check that caps `borrow_index` growth when `borrowed * borrow_index` approaches `i128::MAX` (stopping interest accrual rather than reverting), which preserves repay/withdraw/liquidate paths. At minimum, lower `MAX_BORROW_INDEX_RAY` or enforce per-market caps so `max_cap × MAX_BORROW_INDEX_RAY ≤ i128::MAX` for every listed market. [12](#0-11) [5](#0-4) 

### Proof of Concept
The repository already contains the executable proof — `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs::a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap`:

1. List a 18-decimal market on the steep XLM curve (`slope3` 150%, `optimal_utilization` 75%, `max_utilization` 100%), caps lifted via `lift_caps` to `max_cap_for_decimals(18)`.
2. `BOB` supplies `1e9 * 10^18` raw units of BIG18 (`supply_raw`).
3. `ALICE` supplies COL collateral and borrows 98% of the BIG18 book (`borrow_raw`) — both unprivileged controller `supply`/`borrow` calls.
4. Advance ledger time in `YEAR_SECS` increments, calling the public `update_indexes` entrypoint. Within ≤ 40 years it reverts with `MATH_OVERFLOW` from `scaled_to_original`/`calculate_supplier_rewards`, while `borrow_index < MAX_BORROW_INDEX_RAY`.
5. `withdraw` and `repay` then revert with the same error permanently — the market is bricked with no recovery path, since every mutation and even `clean_bad_debt` accrues first. [13](#0-12) [14](#0-13) [15](#0-14)

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

**File:** common/src/rates/index.rs (L73-88)
```rust
pub fn calculate_supplier_rewards(
    env: &Env,
    params: &MarketParams,
    borrowed: Ray,
    new_borrow_index: Ray,
    old_borrow_index: Ray,
) -> (Ray, Ray) {
    let old_total_debt = borrowed.mul(env, old_borrow_index);
    let new_total_debt = borrowed.mul(env, new_borrow_index);

    let accrued_interest = new_total_debt.checked_sub(env, old_total_debt);

    let protocol_fee = params.reserve_factor.apply_to_ray(env, accrued_interest);
    let supplier_rewards = accrued_interest.checked_sub(env, protocol_fee);

    (supplier_rewards, protocol_fee)
```

**File:** common/src/rates/scaling.rs (L14-16)
```rust
pub fn scaled_to_original(env: &Env, scaled: Ray, index: Ray) -> Ray {
    scaled.mul(env, index)
}
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

**File:** tests/test-harness/tests/controller/large_positions_and_long_horizons.rs (L1-13)
```rust
//! GH-06. One billion whole tokens at 3, 7 and 18 decimals, steep stress rate
//! curves, years of accrual at several utilizations. Every path must clear,
//! the borrow index must track an `e^(r t)` reference within the Taylor bound,
//! accrued interest must be fully assigned, and the exit must pay back what
//! the book says. The last test drives the one cliff the domain has: the ray
//! value of a whale position overflows `i128` long before the index cap.
//!
//! Cells are chosen under that cliff. Utilization is value-based and debt
//! compounds faster than supply, so an untouched market drifts upward: on the
//! XLM curve a book left at 50 percent utilization crosses the optimal point
//! after about ten years and runs away (the reference puts it at x8650 after
//! twenty). Every cell asserts the reference projection stays under the
//! ceiling, so a bad cell fails with a message rather than a host trap.
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

**File:** common/src/constants/pool.rs (L18-23)
```rust
/// Ceiling the borrow index is clamped to after growth, in raw ray units.
pub const MAX_BORROW_INDEX_RAY: i128 = 1_000_000_000_000_000_000_000_000_000_000_000_000;

/// Ceiling the supply index is clamped to after growth, in raw ray units.
/// Equal to [`MAX_BORROW_INDEX_RAY`].
pub const MAX_SUPPLY_INDEX_RAY: i128 = MAX_BORROW_INDEX_RAY;
```

**File:** common/src/types/pool.rs (L193-196)
```rust
            env,
            self.max_borrow_rate <= MAX_BORROW_RATE_RAY,
            CollateralError::MaxBorrowRateTooHigh
        );
```

**File:** common/src/rates/compound.rs (L36-42)
```rust
    let x = Ray::from({
        let r = I256::from_i128(env, rate.raw());
        let d = I256::from_i128(env, delta_ms as i128);
        r.mul(&d)
            .to_i128()
            .unwrap_or_else(|| panic_with_error!(env, GenericError::MathOverflow))
    });
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
