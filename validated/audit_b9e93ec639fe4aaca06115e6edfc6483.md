### Title
RAY value overflow permanently freezes a market: accrual panics before the borrow-index cap, bricking repay, withdraw, and liquidation - (contracts/pool interest accrual / `scaled_to_original`)

### Summary
The closest analog to "a resource is marked consumed with no releaser, so all future allocations fail" in XOXNO Lending is the RAY value-space ceiling in the pool's scaled-share arithmetic. Once `scaled_amount * index` exceeds `i128::MAX`, `scaled_to_original` panics inside every verb that accrues interest — and every verb accrues first — so the market is permanently frozen: no repay, no withdraw, no liquidation, no cleanup. The documented `MAX_BORROW_INDEX_RAY` cap exists to prevent this, but the plain value overflow is reached *before* the index cap engages, so the guard never fires.

### Finding Description
XOXNO Lending accounts for supply and debt as RAY-scaled shares unscaled through `scaled_to_original` during accrual. The protocol documents an index cap (`MAX_BORROW_INDEX_RAY`) that is supposed to bound index growth, but the committed index can grow past ~170x while the index itself is still below the cap, at which point `scaled_to_original` overflows `i128` and panics. The harness test pins this exactly: on a large whale market at sustained ~98% utilization on the XLM rate curve, `update_indexes` eventually fails with `MathOverflow`, and after that `withdraw` and `repay` fail identically because accrual runs first in every entrypoint [1](#0-0) . The test explicitly asserts `last.borrow_index < MAX_BORROW_INDEX_RAY`, i.e., the index cap did not engage before the value overflow [2](#0-1) .

This mirrors the coturn bug structurally: a finite resource pool (relay ports / representable scaled value) is consumed to a point where the allocation path permanently fails, and the mechanism intended to bound consumption (the index cap, like the port-pool free list) never gets the chance to release or gate the resource.

### Impact Explanation
Permanent freezing of user funds and protocol insolvency amplification. Every supplier's tokens in the affected market become permanently unwithdrawable, every borrower's collateral is frozen, liquidations cannot execute (so the bad debt can never be worked out), and `recapitalize` cannot help because it too accrues first. All supplier capital in the bricked market is lost in practice, not merely delayed — there is no unprivileged or privileged code path shown that unwinds accrued state without calling `scaled_to_original`.

### Likelihood Explanation
Low-to-moderate. Reaching the cliff requires a very large market (the test uses a 10^28-scale principal, ~170x the `i128::MAX` headroom baseline) plus sustained near-max utilization over a long accrual horizon, and the attacker must post collateral and hold the borrow — so it is expensive and slow rather than a single-call grief. However, it is reachable purely through unprivileged entrypoints (`supply`, `borrow`, plus `update_indexes` to commit accrual), needs no admin misconfiguration beyond default caps, and once crossed there is no recovery path, which is why Medium is appropriate rather than higher.

Note on uncertainty: the PoC evidence is the in-repo harness test; I did not independently re-derive the accrual chunking math, so the exact crossing point depends on the market's rate curve parameters. The mechanism itself (overflow before index cap, accrual-first panic freezing all verbs) is asserted directly by the test.

### Recommendation
Enforce the index cap *before* unscaling: clamp `borrow_index`/`supply_index` to `MAX_BORROW_INDEX_RAY` at accrual time (or use saturating/checked unscale that returns a bounded error rather than panicking), and add an explicit accrual-time bound check on `scaled * index` so the cap engages before the `i128` ceiling. Alternatively, allow a degraded "panic-safe" exit path (e.g., index-frozen withdrawals) so a market that reaches the ceiling does not strand all deposits.

### Proof of Concept
The repository already contains a self-contained reproduction:

- `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:321` — `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap`: supplies ~10^28 units of an 18-decimal market, borrows ~98% of it against an oversized collateral position, then advances time in year increments until `try_update_indexes_for(&["BIG18"])` fails with `MATH_OVERFLOW` — while asserting `borrow_index < MAX_BORROW_INDEX_RAY` (cap never engaged) and that `try_withdraw_raw` and `try_repay` subsequently fail with the same `MATH_OVERFLOW`, demonstrating the market is frozen [3](#0-2) .

Minimal flow:
1. `supply(BOB, BIG, principal)` — victim liquidity.
2. `supply(ALICE, COL, huge)` + `borrow(ALICE, BIG, ~0.98 * principal)` — attacker drives utilization to the steep curve segment.
3. `update_indexes(...)` repeatedly as time accrues — interest compounds until `scaled * index` overflows.
4. Result: `update_indexes` panics; `withdraw`, `repay`, `liquidate`, `recapitalize`, and `clean_bad_debt` all panic on the same overflow because each accrues first. No exit path remains.

### Citations

**File:** tests/test-harness/tests/controller/large_positions_and_long_horizons.rs (L316-362)
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
