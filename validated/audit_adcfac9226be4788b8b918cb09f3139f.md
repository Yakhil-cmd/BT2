### Title
Debt-value overflow in accrual permanently freezes a market - (File: common/src/rates/simulate.rs)

### Summary
Analogous to CVE-2022-3029 — where a malformed RRDP payload was treated as a fatal error that halted Routinator — the pool's accrual path treats an `i128` value overflow as a fatal panic. `accrue_step` converts scaled debt to original units via `scaled_to_original(env, borrowed, borrow_index)`, which panics with `MathOverflow` once `borrowed × borrow_index` exceeds the RAY value capacity. Since every market mutation runs `interest::global_sync` first, one overflowing accrual permanently bricks the market: no `update_indexes`, `withdraw`, `repay`, `borrow`, liquidation, or `clean_bad_debt` can ever succeed again. The index ceiling (`MAX_BORROW_INDEX_RAY`) does not protect against this because the debt-value overflow is reached before the index cap engages.

### Finding Description
`accrue_step` (common/src/rates/simulate.rs:60) computes `scaled_to_original(env, borrowed, borrow_index)` using checked arithmetic that panics on overflow. `global_sync` (contracts/pool/src/interest.rs:20-33) invokes `accrue_chunk` → `accrue_step` unconditionally when `cache.needs_accrual()` is true, i.e., whenever `last_timestamp < now`. Every state-changing pool entrypoint loads the cache and calls `global_sync` before mutating (documented flow in contracts/pool/README.md:159-168). The production test `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` (tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:320-360) demonstrates the freeze end-to-end: after enough years at ~98% utilization on the XLM rate curve, `update_indexes` fails with `MATH_OVERFLOW`, and subsequently `withdraw` and `repay` fail with the same error because they accrue first. INV-IDX-01 (docs/reference/invariants.md:235-236) acknowledges "Debt-value overflow can still revert accrual before that ceiling is reached."

### Impact Explanation
Permanent freezing of all funds in the affected market. Once `borrowed × borrow_index` exceeds the representable RAY value, every entrypoint that touches the market reverts inside `global_sync` before any state change, and `last_timestamp` can never advance past the failing chunk. Suppliers cannot withdraw, borrowers cannot repay (so liquidations cannot proceed either), and bad-debt cleanup is unreachable. Unlike the Routinator case where a restart was possible, on-chain there is no recovery path short of an upgrade.

### Likelihood Explanation
No privileged action is required: any unprivileged address can create the precondition by supplying and borrowing at high sustained utilization in a high-decimal market (caps can be lifted by governance, but the borrow itself is permissionless). The trigger is purely the passage of ledger time — the overflow is a function of `borrow_index` growth under the configured rate curve, not of attacker input at trigger time. The cost is that the position must be very large (the test uses a $1B-scale book) and accrual must run for years, so this is a griefing-by-capital attack rather than a cheap trigger; severity is bounded by the capital commitment required. Medium.

### Recommendation
Bound the checked conversions in `accrue_step` rather than letting them abort: e.g., clamp `scaled_to_original` inputs or saturate debt value at the RAY value ceiling, and/or lower `MAX_BORROW_INDEX_RAY` (or the rate-curve maximum) so the index cap always engages before `borrowed × borrow_index` can overflow for any market size the caps admit. Alternatively, let `global_sync` stamp `last_timestamp` forward when a chunk would overflow, freezing interest accrual instead of freezing the market.

### Proof of Concept
Existing test: `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:320-360`.

```rust
// Supply a whale-scale book at ~98% utilization on the XLM curve,
// advance time year by year; eventually:
t.try_update_indexes_for(&["BIG18"]);   // Err(MATH_OVERFLOW)
t.try_withdraw_raw(BOB, "BIG18", 1);    // Err(MATH_OVERFLOW) -- accrues first
t.try_repay(ALICE, "BIG18", 1.0);       // Err(MATH_OVERFLOW) -- accrues first
// last.borrow_index < MAX_BORROW_INDEX_RAY: the cap never engaged.
```

Root cause chain: `accrue_step` at common/src/rates/simulate.rs:60 → `scaled_to_original` checked multiply panics → `accrue_chunk` at contracts/pool/src/interest.rs:39-53 propagates → `global_sync` aborts → every market entrypoint reverts before mutating, permanently.