### Title
RAY-value i128 overflow in interest accrual permanently freezes a market — no withdraw, repay, or liquidation can ever execute again - ([File: contracts/pool/src/interest.rs])

### Summary
An integer-overflow crash class (as in CVE-2015-7848, where an overflow aborts the daemon) exists in the pool's accrual path. Every accrual chunk computes total borrowed/supplied value by multiplying RAY-scaled share totals by the index inside `accrue_step` / `scaled_to_original`, and that product panics with `MathOverflow` once `scaled × index` exceeds `i128::MAX`. Because `global_sync` runs before every state-changing verb, once the product overflows the panic is permanent and unconditional: `update_indexes`, `withdraw`, `repay`, `borrow`, `liquidate`, and `clean_bad_debt` all revert on that market forever. The protocol's own harness test demonstrates the cliff and confirms the borrow-index cap never engages before the value overflow.

### Finding Description
The pool stores positions as RAY-scaled shares and unscales them by `scaled.mul(index)` in `scaled_to_original` (`common/src/rates/scaling.rs:14-16`), which uses `mul_div` over `i128` and panics on overflow. Accrual runs in `global_sync` → `accrue_chunk` (`contracts/pool/src/interest.rs:20-53`), which calls `accrue_step`; utilization and accrued totals require the full RAY value `borrowed × borrow_index`, so when a market's raw scaled debt is ~`1e36` RAY (≈1 billion whole tokens at 18 decimals) and the borrow index grows past ~170×, the multiplication exceeds `i128::MAX` (~`1.7e38`) and traps.

There is no bound that prevents reaching this state:

- The borrow index grows monotonically with utilization per the rate curve; `accrue_chunk` updates it via `cache.set_borrow_index(step.borrow_index)` (`contracts/pool/src/interest.rs:50`) without a value-side ceiling check.
- `MAX_BORROW_INDEX_RAY` exists but, as the harness test asserts, the overflow fires *before* the cap engages (`large_positions_and_long_horizons.rs:349-353`).
- `global_sync` is invoked at the head of every verb that touches the book, so the panic cannot be bypassed — callers cannot repay to shrink `borrowed`, withdraw to shrink `supplied`, or liquidate, because the accrual itself is what panics.

An unprivileged attacker reaches this through `supply` (to build the whale book) and `borrow` (to hold utilization at the steep segment of the XLM-style curve, accelerating index growth). `update_indexes` is then permissionlessly callable; once the cliff is crossed, all funds in that market — supplier principal, accrued yield, and the ability to recover collateral — are locked permanently, and outstanding debt can never be liquidated (bad-debt freeze → effective insolvency for that book).

### Impact Explanation
Permanent freezing of funds and protocol insolvency: every supplier's deposit and every borrower's collateral locked in the affected market becomes unrecoverable, and outstanding debt becomes unliquidatable, mirroring the CVE's "crafted input → arithmetic overflow → crash" shape but with a persistent rather than transient effect. The harness test confirms the freeze empirically: after the overflow, `withdraw` and `repay` both revert with `MATH_OVERFLOW` (`large_positions_and_long_horizons.rs:354-356`).

### Likelihood Explanation
Reaching the cliff needs a market whose scaled totals approach `~1e36` RAY and sustained high utilization so the index compounds to ~170× within the documented horizon (a few years at 98% utilization on the steep curve segment per the test). That is whale-scale capital, but the triggering entrypoints (`supply`, `borrow`, `update_indexes`) are all unprivileged, caps can be raised only by governance (rejected as privileged — but note `lift_caps` in the test merely widens listing caps; on a market with high caps the attack is purely capital-bound), and crucially **no recovery path exists once crossed** — the index only moves upward, so the freeze is irreversible rather than temporary. Severity: High (permanent freeze, capital-gated likelihood).

### Recommendation
Enforce a headroom invariant at accrual: before applying `step.borrow_index`/`step.supply_index`, verify `borrowed × new_index` and `supplied × new_index` fit in `i128` (checked/saturating multiply) and clamp the index to the largest safe value (effectively making `MAX_BORROW_INDEX_RAY` a true ceiling at the value ceiling, whichever binds first). Alternatively, cap utilization/borrow growth so `scaled × index` cannot approach the bound, or decompose the value computation to an `I256` intermediate so accrual degrades gracefully instead of trapping.

### Proof of Concept
The in-repo harness test is the executable PoC — `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:321-361`:

```rust
let principal = BILLION * 10i128.pow(18);
t.supply_raw(BOB, "BIG18", principal);            // unprivileged supply, whale book
let debt = principal / 100 * 98;
t.supply_raw(ALICE, "COL", BILLION * 10_000_000 * 3);
t.borrow_raw(ALICE, "BIG18", debt);               // unprivileged borrow → 98% utilization
loop {
    t.advance_time(YEAR_SECS);
    if let Err(e) = t.try_update_indexes_for(&["BIG18"]) { break e; } // permissionless trigger
}
// errors::MATH_OVERFLOW; borrow_index < MAX_BORROW_INDEX_RAY (cap never engages)
assert_contract_error(t.try_withdraw_raw(BOB, "BIG18", 1), errors::MATH_OVERFLOW); // frozen
assert_contract_error(t.try_repay(ALICE, "BIG18", 1.0), errors::MATH_OVERFLOW);    // frozen
```

After the failing accrual, no entrypoint that touches the market can succeed, permanently locking all supplied and collateral value in it.