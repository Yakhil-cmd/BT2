### Title
Accrual panics on `borrowed * borrow_index` i128 overflow before the index cap engages, permanently freezing the market - (File: common/src/rates/index.rs)

### Summary
Analogous to CVE-2021-47485 (unchecked arithmetic on adversary-influenced sizes overflowing kernel memory), the pool's interest accrual multiplies a user-influenced `borrowed` total by `new_borrow_index` in `calculate_supplier_rewards` (`common/src/rates/index.rs:80-83`). `Ray::mul` routes through `mul_div_half_up` (`common/src/math/fp_core.rs:108-118`), which panics with `MathOverflow` when the exact result cannot fit `i128`. The panic fires before the `MAX_BORROW_INDEX_RAY` cap in `update_borrow_index` (`common/src/rates/index.rs:13-19`) can engage, because the value ceiling is hit while the index itself is still well below its cap. Since every controller verb accrues via `global_sync` → `accrue_chunk` → `accrue_step` (`contracts/pool/src/interest.rs:20-53`), once the product crosses the ceiling every subsequent call on that market reverts: no repay, no withdraw, no liquidation, no `clean_bad_debt`.

### Impact Explanation
Permanent freezing of funds for every supplier and borrower in the affected market, plus theft-adjacent loss of unclaimed yield: the market can never be exited or wound down. The harness test `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` (`tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:320-361`) demonstrates exactly this: after the overflow, `try_withdraw_raw`, `try_repay`, and `try_update_indexes_for` all fail with `MATH_OVERFLOW`, and `last.borrow_index < MAX_BORROW_INDEX_RAY`, proving the index cap is unreachable. There is no privileged or unprivileged recovery path since accrual runs unconditionally at the head of every entrypoint.

### Likelihood Explanation
Reachable by unprivileged addresses through ordinary `supply`/`borrow`, but gated by scale and time: the test uses a ~10^9-unit, 18-decimal market at ~98% utilization on the XLM curve and requires multiple years of compounding at high rates before the RAY-value product exceeds `i128::MAX` (~1.7e38). An attacker can accelerate the cliff by supplying a large position, borrowing near the cap, and invoking `update_indexes` (permissionless) to compound — but cannot compress years of real elapsed time. Likelihood is low on real token supplies (caps and `require_cap_within_asset_domain` constrain realistic sizes for most assets, and `max_utilization` limits sustained high utilization), which is why this rates Medium rather than High: severe impact, demanding but non-privileged preconditions.

### Recommendation
Make accrual saturate instead of panicking at the value ceiling. Options: (a) cap `new_total_debt`/`new_index` growth so `borrowed.mul(new_index)` stays in `i128` — e.g., clamp `new_borrow_index` to `min(MAX_BORROW_INDEX_RAY, i128::MAX * RAY / borrowed)` inside `update_borrow_index` or `accrue_step`; (b) in `calculate_supplier_rewards`, fall back to `mul_div_floor_saturating` or a widened `I256` computation that clamps the resulting `Ray` rather than reverting; (c) enforce a per-market borrow/supply cap low enough that `borrowed * MAX_BORROW_INDEX_RAY` cannot overflow, turning the cliff into a listing-time invariant. Any of these keeps exits, repayments, and liquidations alive past the ceiling.

### Proof of Concept
Executable PoC already exists in the repo: `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:320-361`. Conceptual script:

1. List a market with an 18-decimal token and the XLM rate curve; lift supply/borrow caps (`lift_caps`).
2. `supply(BOB, "BIG18", 1e9 * 10^18)` and `borrow(ALICE, "BIG18", 0.98 * principal)` against a separate `COL` collateral position.
3. Advance ledger time in `YEAR_SECS` steps, calling `update_indexes` each step (permissionless entrypoint).
4. After the index grows ~170x, `accrue_step` → `calculate_supplier_rewards` → `borrowed.mul(new_borrow_index)` exceeds `i128` → `MathOverflow`.
5. Confirm freeze: `withdraw`, `repay`, `liquidate`, and further `update_indexes` on `BIG18` all revert with `MATH_OVERFLOW` while `borrow_index < MAX_BORROW_INDEX_RAY`, so no code path can ever reduce `borrowed` or cap the index.