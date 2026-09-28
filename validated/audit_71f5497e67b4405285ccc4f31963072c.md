### Title
Permanent market freeze from `scaled_to_original` RAY-value overflow during accrual - (contracts/pool/src/cache/scale.rs, exercised via `update_indexes`)

### Summary
The analog to the CVE-2019-18976 crash class (an unhandled edge-case that turns a reachable input into a fatal abort) is the accrual-time `i128` value-overflow in the pool's index math: once a market's scaled borrow/supply value grows past the RAY value ceiling, every subsequent accrual panics with `MathOverflow` before the borrow-index cap can engage. Since every pool verb accrues first, the market is permanently frozen — no repay, withdraw, supply, or liquidation is possible.

### Finding Description
Interest accrual in `contracts/pool/src/cache` converts scaled shares back to token values via `scaled_to_original` using the RAY fixed-point helpers in `common/src/math/fp_core.rs`. `mul_div_*` panics with `GenericError::MathOverflow` when the product `scaled * index` (in RAY) exceeds the `i128` value range, and this happens at a *value* ceiling (~170× `i128::MAX` scaled base per the test bounds) that is reached before `MAX_BORROW_INDEX_RAY` is hit.

The pinned behavior is demonstrated by `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` in `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:316-361`, which shows:

- a market at ~98% sustained utilization on the steep tail of the rate curve grows `borrow_index` past ~170× within the modeled horizon;
- the next `update_indexes` fails with `MATH_OVERFLOW` while `borrow_index < MAX_BORROW_INDEX_RAY`, so the index cap never engages;
- `withdraw` and `repay` then fail with the same panic because every entrypoint accrues first (`assert_contract_error(t.try_withdraw_raw(...), MATH_OVERFLOW)` and `try_repay`).

Because accrual is a precondition of `supply`, `borrow`, `withdraw`, `repay`, `liquidate`, `claim_revenue`, and `clean_bad_debt`, a single panicking accrual bricks the whole market book — the same shape as the Asterisk re-invite: one reachable state transition dereferences a value the code assumed could not occur, and thereafter nothing can proceed.

### Impact Explanation
Permanent freezing of funds. All supplier principal and accrued yield in the affected market, plus any collateral/utility value dependent on the pool accounting, becomes unwithdrawable forever; positions cannot be repaid or liquidated, so both suppliers and borrowers are locked. There is no admin verb that bypasses accrual to rescue the book, so this is not a fail-closed temporary pause — the arithmetic precondition is violated on every entrypoint.

### Likelihood Explanation
Requires an unprivileged path only: `supply` + `borrow` to push utilization near the steep tail of the configured curve, then letting the index compound past the value ceiling. The blocker is capital and duration — the test uses a whale-scale market (10^9 × 10^18 units) at ~98% utilization sustained for multiple years. On smaller real-world markets the ceiling is further away, so this is a genuine but capital-intensive condition rather than a cheap griefing vector. Severity: Medium (permanent freeze, but high capital/time requirements and dependent on market reaching extreme scale).

### Recommendation
Bound accrual before the value multiplication overflows: enforce `MAX_BORROW_INDEX_RAY`/`MAX_SUPPLY_INDEX_RAY` inside the chunk loop so the cap clamps the index *before* `scaled_to_original` is evaluated against it, or switch the value conversion to a saturating/`I256`-checked path that clamps the index and lets accrual complete. A defense-in-depth option is to cap per-accrual elapsed time so no single accrual can jump the index into the overflowing range.

### Proof of Concept
Existing harness test `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:321-361` reproduces it end-to-end: seed `BIG18` with whale supply, borrow ~98%, advance one-year steps and call `update_indexes`; `try_update_indexes_for(&["BIG18"])` returns `MATH_OVERFLOW` with `borrow_index < MAX_BORROW_INDEX_RAY`, and subsequent `try_withdraw_raw(BOB, "BIG18", 1)` / `try_repay(ALICE, "BIG18", 1.0)` both fail with `MATH_OVERFLOW`, confirming the market is frozen.

Relevant code: `contracts/pool/src/cache/scale.rs` (`scaled_to_original`), `common/src/math/fp_core.rs:108-118` (`mul_div_half_up` panic path), and the accrual-first pattern in `contracts/pool/src/ops/borrow.rs:42-56`.