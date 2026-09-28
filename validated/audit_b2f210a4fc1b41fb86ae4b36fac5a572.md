### Title
Permanent market freeze: `scaled_to_original` i128 overflow in accrual bricks all entrypoints for a high-utilization market - (File: common/src/rates/simulate.rs)

### Summary
The w3m crash class (attacker-reachable input state → unrecoverable crash/DoS) maps onto the pool's accrual path: once `borrowed_scaled × borrow_index` no longer fits `i128`, `accrue_step` panics with `MathOverflow` inside `global_sync`, and since every state-changing entrypoint accrues first, the market is permanently frozen — no withdraw, repay, liquidate, or further accrual succeeds. The condition is reachable purely through unprivileged supply/borrow and time; the codebase's own test pins the failure and shows it triggers *before* the `MAX_BORROW_INDEX_RAY` cap can engage.

### Finding Description
`accrue_step` opens by valuing the whole book:

```rust
// common/src/rates/simulate.rs:60-61
let borrowed_original = scaled_to_original(env, borrowed, borrow_index);
let supplied_original = scaled_to_original(env, supplied, supply_index);
```

`scaled_to_original` is `scaled.mul(env, index)` (common/src/rates/scaling.rs:14-16), which panics on `i128` overflow (`GenericError::MathOverflow` via `fp_core`). `global_sync` calls `accrue_step` for every elapsed chunk (contracts/pool/src/interest.rs:26-30) and is invoked by `renewed_market` at the head of every mutating pool op — `supply`, `borrow`, `withdraw`, `repay`, `seize_positions`, `claim_revenue`, `recapitalize` — as well as the permissionless `update_indexes` (contracts/pool/README.md:70-71).

The borrow index is capped at `MAX_BORROW_INDEX_RAY` (1e36 raw = 1e9×RAY), but the value product `borrowed × borrow_index / RAY` overflows `i128::MAX` (~1.7e38) well before that cap whenever the scaled debt is large. The pinned test `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` (tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:321-356) drives an 18-decimal market at ~98% utilization on the XLM rate curve, advances time until `update_indexes` fails with `MATH_OVERFLOW`, and asserts both `withdraw` and `repay` then revert with the same error — i.e., the freeze is total and self-perpetuating, since `last_timestamp` never advances and every subsequent call re-runs the same overflowing step.

INV-IDX-01 explicitly acknowledges the residual: "Debt-value overflow can still revert accrual before that ceiling is reached. Bounded indexes do not guarantee representable position or market values" (docs/reference/invariants.md:229-236) — but it is a documented limitation, not a mitigation; nothing caps the *value* domain, only the index.

### Impact Explanation
Permanent freezing of funds. Once the accrual panic is reached, suppliers cannot withdraw, borrowers cannot repay (so they cannot unlock collateral elsewhere), liquidators cannot liquidate, and `claim_revenue`/`recapitalize` also route through `renewed_market`. The market's token custody becomes unreachable contract state — matching the accepted impact classes "permanent freezing of funds" and "contract unable to operate" for that market.

### Likelihood Explanation
Reachable by unprivileged addresses through `supply`/`borrow` (any size subject only to caps, which governance may set high or the attacker can spread across hubs sharing one physical balance) plus elapsed ledger time — no privileged action, no oracle manipulation, no token misbehavior required. However, it demands whale-scale debt (the test uses ~1e27-token books at 18 decimals) and sustained near-max utilization for extended accrual, so it is a capital-intensive, slow-burn trigger rather than a one-transaction exploit. Medium severity aligns with the source CVE rating.

### Recommendation
Make accrual saturate rather than panic on the value bound: clamp `borrowed_original`/`supplied_original` at a representable maximum (or at the debt value implied by `MAX_BORROW_INDEX_RAY`) so `utilization` and the rate computation degrade gracefully instead of trapping. Alternatively, cap minted debt shares (`borrowed`) at listing/borrow time to `i128::MAX / MAX_BORROW_INDEX_RAY`-equivalent headroom so the product can never overflow before the index cap engages. A cheaper partial mitigation is ordering: compute `new_borrow_index` before valuing the book, so once the index hits its ceiling the step can early-return without touching `scaled_to_original`.

### Proof of Concept
Existing pinned reproduction at tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:321-356:

```rust
let principal = BILLION * 10i128.pow(18);
t.supply_raw(BOB, "BIG18", principal);
let debt = principal / 100 * 98;
t.borrow_raw(ALICE, "BIG18", debt);          // 98% utilization, unprivileged

loop { t.advance_time(YEAR_SECS);            // accrual via permissionless update_indexes
       if let Err(e) = t.try_update_indexes_for(&["BIG18"]) { break e; } }

assert_contract_error(failed, errors::MATH_OVERFLOW);
assert_contract_error(t.try_withdraw_raw(BOB, "BIG18", 1), errors::MATH_OVERFLOW);
assert_contract_error(t.try_repay(ALICE, "BIG18", 1.0), errors::MATH_OVERFLOW);
```

The test's own comment states the impact: "the next accrual panics inside `scaled_to_original`. Every verb accrues first, so the market freezes: no repay, no withdraw, no liquidation. The index cap never engages."

One caveat: the panic path is a typed contract error (`MathOverflow`), not an untyped host trap — the DoS comes from the fact that the overflowing state is *persisted* and every recovery path re-executes the same arithmetic, not from a memory-safety crash as in the original w3m report.