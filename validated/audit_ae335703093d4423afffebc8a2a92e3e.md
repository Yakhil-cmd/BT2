### Title
RAY value overflow in interest accrual permanently freezes a large market (panic before the index cap engages) - (File: common/src/rates/index.rs)

### Summary
Like `https-proxy-agent` passing an unsanitized `proxy.auth` string straight into `Buffer()` — turning attacker-influenced input into a process-crashing allocation — the accrual engine multiplies two unsanitized state values (`scaled_shares * index`) with a non-saturating `Ray::mul` and panics on `i128` overflow. Once a market's scaled debt or scaled supply times its index exceeds `i128::MAX`, every state-changing call accrues first and panics, permanently freezing the market. The intended guard, `MAX_BORROW_INDEX_RAY`, never engages because the overflow occurs while computing the *value* that the cap was meant to bound.

### Finding Description
Accrual runs inside `global_sync` → `accrue_chunk` → `accrue_step` on every mutating controller verb (supply, borrow, withdraw, repay, liquidate, clean_bad_debt, flash paths, `update_indexes`). The interest math computes total values as `scaled.mul(env, index)`:

- `calculate_supplier_rewards` does `borrowed.mul(env, new_borrow_index)` and `borrowed.mul(env, old_borrow_index)` (`common/src/rates/index.rs:80-81`).
- `update_supply_index` does `supplied.mul(env, old_index)` (`common/src/rates/index.rs:34`).
- `scaled_to_original` — used by `unscale_supply`/`unscale_borrow` throughout position accounting — is `scaled.mul(env, index)` (`common/src/rates/scaling.rs:14-16`).

`Ray::mul` calls `mul_div_half_up`, which widens to `I256` but then requires the *quotient* to fit `i128`; a product whose value exceeds `~1.7e38` in raw terms panics with `GenericError::MathOverflow`. The borrow index is capped at `MAX_BORROW_INDEX_RAY` in `update_borrow_index` (`common/src/rates/index.rs:13-19`), but that cap only bounds the *index*, not `scaled * index`. A market carrying a very large scaled balance reaches the value ceiling while the index is still far below the cap — the codebase's own test proves the cap never engages and the market freezes (`tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:316-361`): after the panic, `withdraw` and `repay` both revert with `MATH_OVERFLOW` because they accrue first.

Unlike the per-transaction panics rejected by the scope rules (a revert on one's own call is self-DoS), this panic is **state-persistent**: it is a function of stored `borrowed`/`supplied` and monotonically growing indexes, so once crossed, no subsequent call to the market can ever succeed.

### Impact Explanation
Permanent freezing of funds and protocol insolvency:
- All suppliers to the affected (hub, token) book lose access to their deposits forever — `withdraw` reverts at accrual.
- Borrowers cannot `repay`; liquidators cannot `liquidate` or `clean_bad_debt`, so if collateral falls the position cannot be unwound — direct insolvency path.
- `update_indexes` itself is permissionless and reverts, so no recovery verb exists; the index only grows over time, making the freeze irreversible.

### Likelihood Explanation
Reachable by a single unprivileged address with no privileged calls: supply a very large amount to a low-cap-capable market (`lift`-able or high-decimal token), borrow to high utilization against own collateral, then let `update_indexes` accrue. The test demonstrates the cliff at ~98% utilization on the XLM rate curve with a 1e9-token (18-decimal) market after the index grows past ~170x — i.e., it requires whale-scale capital and sustained extreme utilization over a long accrual horizon, and caps/max-utilization must not throttle it. Capital- and time-intensive but fully permissionless and deterministic once set up; severity is bounded to Medium/High rather than Critical by the economic barrier.

### Recommendation
Make the value computations in accrual saturate or bound *before* multiplying, mirroring the existing defensive patterns:
- In `calculate_supplier_rewards` and `update_supply_index`, clamp `borrowed`/`supplied` scaled totals (or use a saturating `try_mul` → cap at a documented `MAX_TOTAL_VALUE_RAY`) so `scaled * index` cannot overflow.
- Alternatively, engage the `MAX_BORROW_INDEX_RAY`/`MAX_SUPPLY_INDEX_RAY` caps based on the pre-multiplication operands so the cap triggers before the value ceiling, and add a regression test asserting the cap path is reachable (the current test at `large_positions_and_long_horizons.rs:320` explicitly asserts it is not).

### Proof of Concept
The repository's own test is the PoC (`tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:321-356`):

```rust
let principal = BILLION * 10i128.pow(18);            // 1e9 units of an 18-decimal token
t.supply_raw(BOB, "BIG18", principal);               // single unprivileged supplier
let debt = principal / 100 * 98;                     // 98% utilization
t.supply_raw(ALICE, "COL", BILLION * 10_000_000 * 3);
t.borrow_raw(ALICE, "BIG18", debt);                  // single unprivileged borrower

loop {
    t.advance_time(YEAR_SECS);                       // permissionless time passage
    if let Err(e) = t.try_update_indexes_for(&["BIG18"]) { break e; }
}
// Panic: GenericError::MathOverflow inside scaled_to_original / borrowed.mul(index)
assert_contract_error(failed, errors::MATH_OVERFLOW);
assert!(book(&t, "BIG18").borrow_index < MAX_BORROW_INDEX_RAY); // cap never engaged
// Permanent freeze — every verb accrues first:
assert_contract_error(t.try_withdraw_raw(BOB, "BIG18", 1), errors::MATH_OVERFLOW);
assert_contract_error(t.try_repay(ALICE, "BIG18", 1.0), errors::MATH_OVERFLOW);
```

Root cause: `Ray::mul` → `fp_core::mul_div_half_up` panics on `i128` overflow (`common/src/math/fp.rs:185-187`), called from `calculate_supplier_rewards` (`common/src/rates/index.rs:80-81`) during `accrue_step` inside `global_sync` (`contracts/pool/src/interest.rs:39-53`), which precedes every market operation — matching the report's pattern of unsanitized input reaching a panicking allocation/multiply and converting it into a persistent denial of service.