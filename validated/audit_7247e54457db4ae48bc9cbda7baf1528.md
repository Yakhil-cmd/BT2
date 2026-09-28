### Title
Borrow-index accrual overflows the RAY value ceiling before the index cap, permanently freezing a whale market - (File: common/src/rates/index.rs)

### Summary
`update_borrow_index` caps the new index at `MAX_BORROW_INDEX_RAY`, but the cap check happens on the index itself, not on the value the index implies. At high utilization on a large market, `borrowed.mul(env, borrow_index)` inside `calculate_supplier_rewards` and `scaled_to_original` overflows `i128` and panics with `MathOverflow` while the index is still below the cap. Since every controller verb accrues the market first, the market becomes permanently inoperable.

### Finding Description
`update_borrow_index` in `common/src/rates/index.rs` computes `new_index = old_index.mul(env, interest_factor)` and only then clamps to `MAX_BORROW_INDEX_RAY` [1](#0-0) . But the same index is multiplied into the scaled debt: `calculate_supplier_rewards` computes `borrowed.mul(env, new_borrow_index)` [2](#0-1) , and `Cache::calculate_utilization` calls `scaled_to_original(&self.env, self.borrowed, self.borrow_index)` [3](#0-2) . `Ray::mul` uses `mul_div_half_up`, which panics on overflow [4](#0-3) .

The product `borrowed_scaled * index / RAY` fits in `i128` only while `borrowed_scaled * index < i128::MAX * RAY`. For a market with roughly `1e27` scaled borrowed shares (e.g. a billion-token 18-decimal asset at ~98% utilization on the steep XLM rate curve), the index needs to grow past ~170x before the value multiplication overflows — well below `MAX_BORROW_INDEX_RAY`, so the cap never saves it. This is the direct analog of the CVE's `bv_len` miscalculation causing a crash: an arithmetic bound on a derived quantity is never checked before it is used, so accrual panics instead of saturating.

The repository's own test proves the freeze: `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` shows `update_indexes` returning `MATH_OVERFLOW` with `borrow_index < MAX_BORROW_INDEX_RAY`, and subsequent `withdraw` and `repay` both panic with the same error because they accrue first [5](#0-4) .

### Impact Explanation
Permanent freezing of funds for the entire market: once the derived debt value crosses the `i128` ceiling, every entrypoint that touches the market — `supply`, `withdraw`, `repay`, `liquidate`, `clean_bad_debt`, `flash_loan`, `update_indexes` — panics during accrual. Suppliers cannot exit, borrowers cannot repay, liquidators cannot close positions. The panic persists for all future timestamps because the index only grows.

### Likelihood Explanation
An unprivileged attacker can set up the preconditions with `supply` and `borrow` alone (no privileged action): supply a very large amount of a high-decimal asset, borrow ~98% of it at a steep-rate market, then let time accrue. The constraints are (a) enormous capital (billion-scale token amounts, requiring a market whose cap permits it — caps can be lifted or the asset may legitimately be huge-supply), and (b) the accrual horizon is wall-clock time, so the freeze cannot be accelerated; the test needed years of simulated accrual. The attacker also cannot recover a frozen market, but can grief all co-suppliers' funds at the cost of leaving their own borrow position locked. Combined severity: Medium-High; I rate it **Medium** given capital and time requirements.

### Recommendation
Saturate rather than panic on the value ceiling: use `mul_div_*_saturating` (already available as `fp_core::mul_div_floor_saturating` and used in `update_supply_index`/`protocol_fee_shares` [6](#0-5) ) inside `scaled_to_original` and the `borrowed.mul(...)` sites in `calculate_supplier_rewards` and `calculate_utilization`, or pre-clamp the effective index to `min(new_index, MAX_BORROW_INDEX_RAY, i128-safe bound for current borrowed)` before multiplying. A regression test asserting accrual succeeds at `borrow_index == MAX_BORROW_INDEX_RAY` with whale-scale `borrowed` would pin the fix.

### Proof of Concept
Covered by the existing harness test `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:320-361`: supply `1e27` atomic units of an 18-decimal asset, borrow 98%, advance ledger time repeatedly; `try_update_indexes_for(["BIG18"])` fails with `MATH_OVERFLOW` at `borrow_index ≈ 170x` (< `MAX_BORROW_INDEX_RAY`), and `try_withdraw_raw`/`try_repay` subsequently fail identically — the market is frozen.

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

**File:** common/src/rates/index.rs (L41-44)
```rust
    let grown = fp_core::mul_div_floor_saturating(env, new_value.raw(), RAY, supplied.raw());

    let bounded_old = old_index.raw().min(MAX_SUPPLY_INDEX_RAY);
    Ray::from(grown.min(MAX_SUPPLY_INDEX_RAY).max(bounded_old))
```

**File:** common/src/rates/index.rs (L80-83)
```rust
    let old_total_debt = borrowed.mul(env, old_borrow_index);
    let new_total_debt = borrowed.mul(env, new_borrow_index);

    let accrued_interest = new_total_debt.checked_sub(env, old_total_debt);
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

**File:** common/src/math/fp.rs (L50-52)
```rust
    pub fn mul(self, env: &Env, other: Ray) -> Ray {
        Ray(fp_core::mul_div_half_up(env, self.0, other.0, RAY))
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
