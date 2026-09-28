### Title
RAY-domain value overflow in accrual permanently freezes a market before the borrow-index cap can engage - (File: common/src/rates/scaling.rs)

### Summary
Every controller verb (`supply`, `borrow`, `withdraw`, `repay`, `liquidate`, `clean_bad_debt`, `flash_position`, `multiply`, `update_indexes`) accrues interest first. Accrual computes `borrowed_original = scaled * borrow_index` via `scaled_to_original`, which panics with `GenericError::MathOverflow` whenever the product exceeds `i128::MAX` — i.e. when the debt's RAY value exceeds ~170.14 billion whole tokens. On a steep utilization curve at sustained ~98% utilization, the borrow index grows fast enough that this value ceiling is hit **before** `MAX_BORROW_INDEX_RAY` (10^9 × RAY) ever engages, so the documented safety cap cannot stop it. Once `borrowed_scaled_ray * borrow_index` overflows, every subsequent accrual panics and the market is permanently bricked: no repayment, withdrawal, liquidation, or bad-debt cleanup can ever execute.

### Finding Description
`scaled_to_original` in `common/src/rates/scaling.rs:14-16` is a plain `Ray::mul` that panics on overflow, with no saturation or clamping. It is invoked unconditionally at the top of each accrual step (`common/src/rates/simulate.rs:60-61`: `scaled_to_original(env, borrowed, borrow_index)` and the same for `supplied`). `accrue_step` runs inside every index update (`simulate_update_indexes_body`), which every user-facing entrypoint performs before touching balances. The borrow index compounds via `compound_interest`/`update_borrow_index` at up to `MAX_BORROW_RATE_RAY` = 2 RAY (200% APR), chunked per `MAX_COMPOUND_DELTA_MS` = one year (`common/src/rates/compound.rs:13`). The repo's own harness test `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` (tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:320-361) demonstrates the freeze end-to-end: `try_update_indexes`, `try_withdraw_raw`, and `try_repay` all revert with `MATH_OVERFLOW`, and `last.borrow_index < MAX_BORROW_INDEX_RAY` confirms the cap never engages.

### Impact Explanation
Permanent freezing of user funds and protocol insolvency for the affected market. Once `borrowed_scaled_ray * borrow_index >= i128::MAX`, the panic in `scaled_to_original` precedes every state transition: suppliers can never withdraw, borrowers can never repay, liquidators cannot `liquidate` or run `clean_bad_debt`, and `recapitalize` cannot restore backing. All supplied cash in that (hub, token) book is locked forever. An attacker who caused the overflow additionally escapes liquidation of their own underwater debt. The situation is irreversible because accrual is the first step of every entrypoint — there is no path that skips it or clamps the index first.

### Likelihood Explanation
Reachable by a single unprivileged address, though capital-intensive:

1. Attacker supplies a very large amount of a high-decimals asset (18-decimals, cap ceiling ~1.7e11 whole tokens; e.g. 1e9 whole tokens = 1e27 native units) via `controller.supply`, keeping the market near the admitted cap.
2. From a collateralized position, attacker calls `borrow` to push utilization to ~98%, or uses `multiply`/`flash_position` to amplify the debt in one transaction.
3. Attacker then calls `update_indexes` periodically (permissionless). With utilization pinned high on a steep kinked curve, each `accrue_step` multiplies `borrow_index` by up to ~e^2 per year-chunk while `borrowed_scaled_ray` is already ~1e36 ray. `scaled_to_original` overflows once the index exceeds ~170× — a few years of compounding at the steep segment, as the harness test confirms (loop reaches the cliff well under 40 years; the test asserts years ≤ 40 and observes the index far below `MAX_BORROW_INDEX_RAY`).
4. From that point the market is permanently frozen; every verb reverts at accrual.

The attacker's own debt also cannot be repaid or liquidated, so they forfeit their collateral — but they permanently destroy/lock the much larger supplier principal, and can grief the market for a bounded cost. Documentation (`docs/reference/formulas.md:433-437`) acknowledges that "value overflow can occur before the index ceiling," but the deployed behavior is worse than documented: the test comment itself notes "the index cap did not engage before the value overflow," i.e. the intended mitigation at `MAX_BORROW_INDEX_RAY` is unreachable and provides zero protection.

### Recommendation
Clamp the borrow index in `update_borrow_index` at `MAX_BORROW_INDEX_RAY` **before** the product can overflow, and make accrual skip gracefully once capped ("at the borrow-index ceiling, further accrual produces no borrower interest" — the documented intent that never executes). Alternatively, in `accrue_step`, detect when `scaled_to_original` would exceed the i128 domain and pin `borrow_index`/`supply_index` to their caps, so `repay`/`withdraw`/`liquidate`/`clean_bad_debt` remain callable. A saturating unscale for the accrual inputs (rather than the panicking `Ray::mul`) would also keep exit paths alive even if the index is never explicitly capped.

### Proof of Concept
The repo's own test is a working PoC (tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:320-361):

```rust
let principal = BILLION * 10i128.pow(18);            // attacker supply, 18-dec asset
t.supply_raw(BOB, "BIG18", principal);
let debt = principal / 100 * 98;                      // 98% utilization
t.supply_raw(ALICE, "COL", BILLION * 10_000_000 * 3);
t.borrow_raw(ALICE, "BIG18", debt);

loop {
    t.advance_time(YEAR_SECS);
    if t.try_update_indexes_for(&["BIG18"]).is_err() { break; }  // MathOverflow
}
// Frozen forever:
assert_contract_error(t.try_withdraw_raw(BOB, "BIG18", 1), MATH_OVERFLOW); // supplier exit reverts
assert_contract_error(t.try_repay(ALICE, "BIG18", 1.0), MATH_OVERFLOW);    // repay reverts
// book.borrow_index < MAX_BORROW_INDEX_RAY: the cap never engaged
```

Root cause chain: `update_indexes` → `accrue_step` (`common/src/rates/simulate.rs:60`) → `scaled_to_original` (`common/src/rates/scaling.rs:14-16`) → `Ray::mul` → `MathOverflow`, executed before any balance mutation in every entrypoint.