### Title
Permanent market freeze: `scaled * borrow_index` overflows `i128` before `MAX_BORROW_INDEX_RAY` cap can engage, panicking every accrual-gated entrypoint - (File: common/src/rates/index.rs)

### Summary
Analogous to GHSA-wmxc-v39r-p9wf — where a malformed task gets permanently stuck in a queue and crash-loops every handler — a market's scaled debt and borrow index together form a poisoned state that makes every subsequent accrual panic with `MathOverflow`. Every controller/pool money verb (`withdraw`, `repay`, `borrow`, `liquidate`, `flash_loan`, `update_indexes`, `clean_bad_debt`, `claim_revenue`) runs `global_sync` → `accrue_chunk` → `accrue_step` first, so once the RAY-valued product `borrowed * new_borrow_index` exceeds `i128::MAX`, the entire market is frozen forever. The `MAX_BORROW_INDEX_RAY` cap in `update_borrow_index` never engages because the value-side product overflows before the index reaches 1e36. An unprivileged address reaches this by supplying a large position and borrowing near maximum utilization on a high-decimal, high-cap market, then waiting for compounding.

### Finding Description
Accrual is chunked and executed inside `global_sync` before any operation in `contracts/pool/src/interest.rs:20-33`. Each chunk calls `accrue_step`, which computes `new_total_debt = borrowed.mul(env, new_borrow_index)` inside `calculate_supplier_rewards` at `common/src/rates/index.rs:81`, and utilization via `scaled_to_original(borrowed, borrow_index)` in `contracts/pool/src/cache/scale.rs:23`. `Ray::mul` panics with `GenericError::MathOverflow` when `scaled * index / RAY` exceeds `i128::MAX`. The index growth is capped by `update_borrow_index` at `common/src/rates/index.rs:15-18`, but the cap applies to the index, not to the `scaled × index` product. For a whale-scale market (scaled debt near ~1e36, e.g., an 18-decimal token with governance-lifted caps), the product overflows at an index of only ~170×RAY — far below `MAX_BORROW_INDEX_RAY`. The harness test proves the end state: after the cliff, `withdraw` and `repay` both fail with `MATH_OVERFLOW` because every verb accrues first (`tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:316-361`). Unlike the Temporal case there is no removable poisoned task: the overflow is a monotone function of the stored index and scaled balances, so no transaction can ever succeed again on that market.

### Impact Explanation
Permanent freezing of funds: all suppliers' deposits and all borrowers' collateral in the affected (hub, token) market become unrecoverable — withdraws, repays, liquidations, bad-debt cleanup, and revenue claims all revert on the same accrual panic. Bad debt in the frozen market can never be socialized (`apply_bad_debt_to_supply_index` is behind the same `global_sync` path), so the pool cannot even unwind the market; protocol revenue booked as supply shares is frozen with it.

### Likelihood Explanation
Low-to-moderate. Requires an 18-decimal market listed with supply/borrow caps near `max_cap_for_decimals`, an attacker (or organic whale) holding debt-scaled balances on the order of 1e36 RAY, and sustained near-max utilization on a steep rate curve for the index to compound to the cliff (the test required advancing simulated years at 98% utilization on the XLM-style curve; it never triggered within 40 years at lower scale). Accrual cannot be accelerated — `MAX_COMPOUND_DELTA_MS` chunking ties growth to real ledger time — so exploitation is passive and slow rather than a single crafted call. Still, it needs only ordinary `supply`/`borrow` calls, no privileges, and the failure is irreversible once reached, matching Medium.

### Recommendation
- Make the accrual path fail-safe: use saturating/widened multiplication for `borrowed * borrow_index` inside `calculate_supplier_rewards` and `scaled_to_original` when called from `global_sync`, clamping the computed debt to `i128::MAX` (or capping the *debt value* at the point the product would overflow) instead of panicking — mirroring `mul_div_floor_saturating` already used in `calculate_scaled_cap` and `protocol_fee_shares` (`common/src/rates/scaling.rs:26-33`, `common/src/rates/index.rs:94-99`).
- Alternatively, lower `MAX_BORROW_INDEX_RAY` to a value that guarantees `max_scaled_balance * MAX_BORROW_INDEX_RAY / RAY <= i128::MAX` for the largest reachable scaled balance, so the index cap provably engages before the value overflow.
- Add a regression test asserting a pinned index no longer bricks `withdraw`/`repay`/`clean_bad_debt`.

### Proof of Concept
Reproduced by the existing harness test `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` (`tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:321-361`):

```rust
let principal = BILLION * 10i128.pow(18);
t.supply_raw(BOB, "BIG18", principal);          // 18-dec market, caps lifted
t.borrow_raw(ALICE, "BIG18", principal / 100 * 98); // ~98% util on steep curve
loop {
    t.advance_time(YEAR_SECS);
    if let Err(e) = t.try_update_indexes_for(&["BIG18"]) { break e; }
}
// e = MathOverflow; last.borrow_index < MAX_BORROW_INDEX_RAY (cap never engaged)
assert_contract_error(t.try_withdraw_raw(BOB, "BIG18", 1), errors::MATH_OVERFLOW);
assert_contract_error(t.try_repay(ALICE, "BIG18", 1.0), errors::MATH_OVERFLOW);
```

After the cliff, the poisoned state (`borrowed`, `borrow_index` in market storage) is itself the malformed task: `global_sync` re-panics on every chunk for every caller, permanently, with no operator-level mitigation analogous to removing a workflow.