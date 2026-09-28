### Title
Sustained borrow-index growth overflows the RAY value domain and permanently freezes the market before `MAX_BORROW_INDEX_RAY` can cap accrual - (File: contracts/pool/src/interest.rs)

### Summary
A zip-bomb-style amplification exists in the pool's chunked interest accrual: a small per-step compounding factor applied repeatedly to a very large RAY book expands `scaled × index` past the `i128` domain inside `scaled_to_original`, panicking in `global_sync`. Because every state-changing verb accrues first, the panic permanently freezes the market — suppliers cannot withdraw, borrowers cannot repay, liquidations and `clean_bad_debt` cannot run — even though the intended `MAX_BORROW_INDEX_RAY` cap was designed to stop index growth.

### Finding Description
`global_sync` in `contracts/pool/src/interest.rs:20-33` chunks elapsed time into `MAX_COMPOUND_DELTA_MS` windows and calls `accrue_chunk`, which delegates to `accrue_step` in `common/src/rates/simulate.rs:51-94`. The first step of each chunk computes `scaled_to_original(env, borrowed, borrow_index)` (`common/src/rates/scaling.rs`), a `mul_div` of two RAY-scaled values whose intermediate result is bounded by `i128` per `docs/reference/formulas.md` ("Unrepresentable results raise `MathOverflow`").

`update_borrow_index` caps the index itself at `MAX_BORROW_INDEX_RAY` (10^36), but that cap only guards the index — not the product `borrowed × borrow_index`. On a whale-scale market (order 10^9 whole tokens at 18 decimals, i.e. ~10^54 RAY of scaled debt), the borrow index reaches roughly 170× RAY — still far below the 10^36 cap — while `borrowed × borrow_index / RAY` already exceeds `i128::MAX`. From that point every `accrue_step` panics with `MathOverflow`.

The protocol's own test demonstrates this end-to-end: `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:321-360` (`a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap`) supplies `BILLION * 10^18` of an 18-decimal asset on the XLM rate curve at 98% utilization, advances time, and observes `update_indexes`, `withdraw`, and `repay` all revert with `MATH_OVERFLOW` while `borrow_index < MAX_BORROW_INDEX_RAY` — confirming the cap never engages and the freeze is permanent, not a transient budget failure.

### Impact Explanation
Permanent freezing of funds for every participant in the affected market. Once `borrowed × borrow_index` crosses the `i128` boundary, `global_sync` panics on every subsequent invocation, and since accrual runs at the top of every pool verb (supply, withdraw, borrow, repay, seize, bad-debt write-down, recapitalize), no user can exit and no liquidator or keeper can touch the market. All supplier principal and accrued yield in that market is unrecoverable — a permanent freeze, not a fail-closed pause that governance can lift, because the state itself can no longer be advanced.

### Likelihood Explanation
An unprivileged attacker can drive this deliberately. The path requires only `supply` + `borrow` (or `flash_loan`/`multiply` to lever the utilization) plus permissionless `update_indexes` to keep accruing; no governance action, oracle manipulation, or privileged role is needed. The preconditions are demanding — a market holding on the order of billions of whole units of a high-decimal token sustained near-maximum utilization — and interest must accrue for an extended wall-clock period while the index grows ~170×. That places it below the trivially-reachable bugs, but the attack requires capital and patience rather than privilege, the curve configuration is an existing listed-market parameter, and the outcome is irreversible once crossed. This is a genuine amplification hazard: a bounded compounding input decompresses into an arithmetic state the contract can never process again.

### Recommendation
Cap accrual on the *value* side, not just the index side. Concretely:
- In `accrue_step`/`update_borrow_index`, additionally clamp `borrowed` (or skip accrual and mark the market) when `scaled_to_original(borrowed, new_borrow_index)` would exceed the `i128` domain — e.g. compute the step with a saturating/`I256` check and set `borrow_index` to the largest value whose product with `borrowed` still fits.
- Alternatively, floor/cap total market size at listing/borrow time so that `total_borrowed_ray × MAX_BORROW_INDEX_RAY` can never overflow, enforcing a per-market supply/borrow ceiling derived from `i128::MAX / MAX_BORROW_INDEX_RAY`.
- Make `global_sync` fail-soft: if a chunk's arithmetic overflows, pin the index at the last representable value and stop accruing rather than panicking, so exits and liquidations remain possible.

### Proof of Concept
The existing harness test `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` (`tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:321-360`) is a complete PoC:

```rust
let principal = BILLION * 10i128.pow(18);          // 1e9 whole tokens, 18 decimals
t.supply_raw(BOB, "BIG18", principal);
t.supply_raw(ALICE, "COL", BILLION * 10_000_000 * 3);
t.borrow_raw(ALICE, "BIG18", principal / 100 * 98); // ~98% utilization

loop {
    t.advance_time(YEAR_SECS);
    if let Err(e) = t.try_update_indexes_for(&["BIG18"]) { break e; }
}
// panics with MATH_OVERFLOW while borrow_index < MAX_BORROW_INDEX_RAY
assert_contract_error(t.try_withdraw_raw(BOB, "BIG18", 1), errors::MATH_OVERFLOW);
assert_contract_error(t.try_repay(ALICE, "BIG18", 1.0), errors::MATH_OVERFLOW);
```

The panic originates in `scaled_to_original(borrowed, borrow_index)` inside `accrue_step` (`common/src/rates/simulate.rs:60`), reached via `global_sync` → `accrue_chunk` (`contracts/pool/src/interest.rs:26-48`). After the overflow point, every accrue-first verb reverts, freezing all supplier and borrower funds in the market permanently.