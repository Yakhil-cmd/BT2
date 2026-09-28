### Title
Permanent market freeze via RAY-domain overflow in `scaled_to_original` during mandatory accrual — (File: contracts/pool/src/cache/scale.rs)

### Summary
The CVE class is a remotely triggered, repeatable denial of service (hang/crash of the victim component). In XOXNO Lending the analog is a permanent `MathOverflow` panic inside interest accrual: once a large market's scaled debt or supply multiplied by its index exceeds the `i128` RAY domain, every state transition that touches the market reverts, because every verb accrues first. Any unprivileged user can drive a market into this state by supplying and borrowing at scale and sustaining high utilization; once reached, no one — including liquidators and suppliers — can ever interact with that market again.

### Finding Description
All pool operations load a `Cache` and synchronize interest before doing anything else. `Cache::calculate_utilization` converts the market totals back to asset value via `scaled_to_original(&self.env, self.borrowed, self.borrow_index)` and `scaled_to_original(&self.env, self.supplied, self.supply_index)` (contracts/pool/src/cache/scale.rs:23-24), which multiplies a RAY share amount by a RAY index inside the `i128` domain and panics with `MathOverflow` on overflow. This helper runs inside `accrue_step`, which is called by `accrue_chunk` → `global_sync` (contracts/pool/src/interest.rs:20-53), which itself is invoked unconditionally at the top of every market op — `supply`, `borrow`, `withdraw`, `repay`, `flash_loan`, `seize`, `recapitalize` — and by the keeper entrypoint `accrue`/`update_indexes` (contracts/pool/src/ops/market.rs:65-72).

Because accrual is chunked (`MAX_COMPOUND_DELTA_MS`) rather than capped in value, the borrow/supply index can grow to roughly `10^9 × RAY` before the `MAX_BORROW_INDEX_RAY` ceiling matters, and the *value* product `shares × index` overflows `i128` long before the index cap engages. The panic aborts the whole transaction, so `last_timestamp` never advances, the overflow persists, and every subsequent call — including repayment and liquidation — hits the identical panic. This is proven by the harness test `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` (tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:316-362), which shows `update_indexes`, `withdraw`, and `repay` all failing with `MATH_OVERFLOW` once the cliff is crossed.

### Impact Explanation
Permanent freezing of user funds and protocol insolvency in the affected `(hub, token)` market:

- Suppliers can never withdraw: `withdraw` accrues first and panics.
- Borrowers cannot repay and liquidators cannot liquidate, so bad debt accrues unboundedly and can never be cleaned (`clean_bad_debt`/`force_socialize_bad_debt` also load the same cache and sync).
- `recapitalize` cannot repair the book because it too accrues first.
- The market is dead forever — there is no recovery path, since the overflow is recomputed from stored state on every call and `mark_accrued` is never reached.

### Likelihood Explanation
Reachable by a single unprivileged address using only `supply` and `borrow` (and time). The requirements are economic, not privileged: a market with ~170 billion units of an 18-decimal asset at sustained ~98% utilization on a steep rate curve crosses the value ceiling before the index cap — the harness test demonstrates the cliff within the modeled horizon. The attacker's own funds are frozen too, but a griefer who has already borrowed near the utilization maximum externalizes the loss onto the market's suppliers: the borrowed tokens were already extracted, while all remaining supplier principal is locked permanently. The requirement of a whale-scale book keeps this Medium rather than High, matching the CVE's 4.9 class.

### Recommendation
Handle the overflow in `scaled_to_original` (and the `accrue_step` path that calls it) gracefully:

- Saturate or clamp the computed value at `i128::MAX` when `shares × index` overflows, and/or clamp utilization at `Ray::ONE` so accrual continues on a saturated book.
- Alternatively, cap accrual when the borrow index reaches `MAX_BORROW_INDEX_RAY` *before* computing the value product, so the index ceiling actually protects the multiplication.
- Add a regression test asserting that `update_indexes`, `repay`, and `withdraw` remain callable at the value-domain boundary rather than panicking.

### Proof of Concept
Reproduced by `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:316-362`:

1. Create a market for an 18-decimal asset with a steep (XLM-style) rate curve; lift supply/borrow caps.
2. `supply_raw(BOB, "BIG18", 170e9 * 10^18)`; `supply_raw(ALICE, "COL", …)` for collateral; `borrow_raw(ALICE, "BIG18", 98% of supplied)`.
3. Advance ledger time year-by-year calling `update_indexes`. At the year where `borrowed × borrow_index` exceeds the `i128` RAY domain, `try_update_indexes_for` returns `MathOverflow` while `borrow_index < MAX_BORROW_INDEX_RAY` (the index cap never engages).
4. Thereafter `try_withdraw_raw(BOB, "BIG18", 1)` and `try_repay(ALICE, "BIG18", 1.0)` both revert with `MATH_OVERFLOW` permanently — supplier principal and the market are frozen forever.