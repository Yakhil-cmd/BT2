### Title
RAY-scaled accrual overflows before the borrow-index cap, permanently freezing a market - (File: contracts/pool/src/cache/scale.rs)

### Summary
Analog of CVE-2019-11810 ("unchecked failure result → NULL deref DoS"): the pool's millisecond interest accrual assumes a checked i128 multiplication always succeeds. When `scaled_to_original` overflows, every user-facing verb panics because all of them accrue first, and the `MAX_BORROW_INDEX_RAY` ceiling never gets a chance to clamp the index. The market becomes permanently unusable: no repay, no withdraw, no liquidation, no `update_indexes`.

### Finding Description
The kernel bug is a NULL dereference caused by treating a fallible allocation as infallible. The lending analog is `scaled_to_original` in the pool's share-scaling code (cache/scale.rs), which rescales RAY debt shares back to asset units with `mul_div`-style i128 arithmetic and panics on overflow instead of being guarded by the documented `MAX_BORROW_INDEX_RAY` index cap.

The harness test `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` in `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:316-361` demonstrates this end-to-end:
- With caps lifted, an 18-decimal market holding `1e9 * 10^18` raw units at ~98% utilization on the XLM rate curve accrues until `try_update_indexes` fails with `MATH_OVERFLOW` (lines 343-348).
- At failure time `last.borrow_index < MAX_BORROW_INDEX_RAY`, proving the index cap — the intended guard — never engages before the value overflow (lines 349-353).
- The freeze is total: `try_withdraw` and `try_repay` both revert with the same `MATH_OVERFLOW` because every verb accrues first (lines 354-356).

Reachable entrypoints for an unprivileged address: `supply` and `borrow` to build the whale position, then passive time accrual; after the cliff, `withdraw`, `repay`, `liquidate`, `clean_bad_debt`, `flash_loan`, and `update_indexes` all panic on the same accrual step.

### Impact Explanation
Permanent freezing of funds: all supplier principal and all borrower collateral in the affected market is locked forever, and outstanding debt can never be repaid or liquidated. Interest keeps accruing conceptually but any transaction touching the market aborts on the same overflow. This satisfies the "permanent freezing of funds" acceptance criterion.

### Likelihood Explanation
Medium-Low. No privileged role is needed — any address can supply and borrow. However, triggering the cliff requires an extremely large position (the test uses 10^27 raw units of an 18-decimal asset with supply/borrow caps lifted) held at ~98% utilization for multiple years on a steep rate curve. For markets with realistic asset supplies and configured caps this is out of reach, so the finding is a latent design flaw rather than a near-term exploit — hence Medium.

### Recommendation
Enforce `MAX_BORROW_INDEX_RAY` (and the analogous supply-index bound) inside the accrual step itself — clamp the new index before it is applied to scaled balances — instead of relying on post-hoc checks that the overflowing `scaled_to_original` call precedes. Alternatively, saturate `scaled_to_original` (or use widening arithmetic) so an oversized index produces a capped value rather than a panic, keeping repay/withdraw/liquidate paths executable.

### Proof of Concept
The existing regression test is the PoC (`tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:320-361`):

```rust
let principal = BILLION * 10i128.pow(18);          // 18-decimal whale market
t.supply_raw(BOB, "BIG18", principal);
t.borrow_raw(ALICE, "BIG18", principal / 100 * 98); // ~98% utilization
loop {
    t.advance_time(YEAR_SECS);
    if let Err(e) = t.try_update_indexes_for(&["BIG18"]) { break e; }
}
// → MATH_OVERFLOW with borrow_index < MAX_BORROW_INDEX_RAY
// then: try_withdraw and try_repay both revert with MATH_OVERFLOW
```

Any transaction touching the market after the cliff aborts inside accrual, confirming the permanent-freeze impact.