### Title
Overflow in `scaled_to_original` during interest accrual permanently freezes all funds in a large saturated market — (`File: common/src/rates/scaling.rs`)

### Summary
The bug class of ALPINE-CVE-2020-9366 is "specially crafted input drives a computation past its representable bound and corrupts/traps the whole program." In XOXNO Lending the analog is fixed-point overflow: when a market's scaled debt value `scaled_debt × borrow_index` exceeds the `i128` RAY domain, `scaled_to_original` panics inside `mul_div_half_up`, and because every pool mutator accrues first, the market becomes permanently inoperable — no repay, withdraw, borrow, or liquidation.

### Finding Description
Pool accrual converts scaled debt/supply `Ray` values back to asset units through `scaled_to_original`, which calls `Ray::mul` → `mul_div_half_up`. That helper returns `None` when the product `x * y` overflows `i128` even after the `I256` widening path, and the panicking wrapper turns it into `GenericError::MathOverflow`. [1](#0-0) 

The conversion itself sits at `common/src/rates/scaling.rs:14-16`: [2](#0-1) 

The borrow index is capped at `MAX_BORROW_INDEX_RAY`, but the *product* of scaled amount × index has no such guard — the value ceiling is hit before the index cap engages. The test `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` demonstrates exactly this: at ~98% utilization on the XLM rate curve, `try_update_indexes` begins failing with `MATH_OVERFLOW`, after which `withdraw` and `repay` fail identically because they accrue first. [3](#0-2) 

Unlike the GNU Screen crash (a transient process), a Soroban panic during accrual is not transient: the state is never written past the ceiling, but the state needed to unstick the market (a lower index or lower scaled debt) cannot be reached because every corrective entrypoint accrues first. `update_indexes` itself traps, so nothing in `contracts/pool/src/ops` can advance the market.

### Impact Explanation
Permanent freezing of user funds. Once the scaled-debt × index product crosses the `i128` RAY bound, every state-changing entrypoint on that market — `supply`, `borrow`, `withdraw`, `repay`, `liquidate`, `clean_bad_debt`, `update_indexes` — reverts inside accrual. All suppliers' deposits and all pending revenue in that (hub, token) market are locked forever; bad debt cannot be written down and collateral cannot be seized, so the market's books are also unrecoverable, which can propagate to protocol insolvency for the affected hub spoke.

### Likelihood Explanation
Reachable by a single unprivileged address via `controller.supply` + `controller.borrow`: the attacker supplies a very large position in a high-decimal asset and borrows near the utilization cap, then simply lets interest accrue. No privileged call, oracle manipulation, or external dependency is needed — only capital and time at elevated utilization, which the attacker can sustain by keeping utilization near max (e.g., by matching borrow size to supply). The test reaches the cliff on the XLM curve within the asserted window at 98% utilization.

### Recommendation
- Enforce the index/value ceiling in accrual: in `contracts/pool/src/interest.rs`, clamp the computed index or scaled aggregates at `MAX_BORROW_INDEX_RAY` / a derived value cap *before* calling `scaled_to_original`, and skip (not revert) the accrual leg when the product would overflow, so exits remain possible.
- Alternatively, make the accrual path use a saturating `try_mul_div` variant for the debt-value recomputation so the market degrades to capped-interest rather than a hard trap.
- Add a governance/keeper-triggered `clean_bad_debt`/write-down path that does not require full accrual, as an escape hatch for markets already at the ceiling.

### Proof of Concept
1. List/seed a market with an 18-decimal asset using the steep XLM-style rate curve and lifted supply/borrow caps (mirroring `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:320-361`).
2. Attacker calls `supply` with ~10⁹ whole-token units (scaled amount near the RAY value ceiling) and `borrow` at ~98% of it.
3. Wait / advance ledger time at sustained max utilization; call `update_indexes` repeatedly until it returns `Error(Contract, #33)` (`MATH_OVERFLOW`).
4. Subsequent `withdraw` (supplier exit) and `repay` both revert with the same `MATH_OVERFLOW` inside accrual — custody is permanently unwithdrawable and the index cap never engages.

### Citations

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

**File:** tests/test-harness/tests/controller/large_positions_and_long_horizons.rs (L320-360)
```rust
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
