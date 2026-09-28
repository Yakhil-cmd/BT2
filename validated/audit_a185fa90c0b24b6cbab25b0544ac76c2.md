### Title
RAY value overflow in accrual panics before the borrow-index cap engages, permanently freezing a market - (File: common/src/rates/index.rs)

### Summary
The bug class is a crash on untrusted input (untrusted pointer dereference → segfault in mruby). On Soroban the analog is a host/contract panic reachable from permissionless input. Here, interest accrual computes `supplied * index` and `borrowed * index` as raw `i128` products inside `Ray::mul` (`common/src/math/fp.rs`, `fp_core::mul_div_half_up`), which panics with `GenericError::MathOverflow` on overflow. Because the panic occurs on the *product* `scaled_shares × index`, it triggers well before the index itself reaches `MAX_BORROW_INDEX_RAY` (1e36), so the clamp in `update_borrow_index` (`common/src/rates/index.rs:13-19`) never engages. Every state-changing verb accrues first via `interest::global_sync` (`contracts/pool/src/interest.rs:20-33`), so once the product overflows the market is permanently bricked.

### Finding Description
`update_supply_index` (`common/src/rates/index.rs:34`) and `calculate_supplier_rewards` (`common/src/rates/index.rs:80-83`) multiply `scaled` RAY balances by the index using `Ray::mul`, which is non-saturating and panics when `x * y` exceeds `i128::MAX`. Scaled totals are `amount × RAY / 10^decimals`, so for an 18-decimal asset a 1e9-token market carries scaled totals ≈ 1e36 raw; multiplying by an index of only ~170×RAY already exceeds `i128::MAX` (≈1.7e38). The cap `MAX_BORROW_INDEX_RAY = 1e36` (i.e. index up to 1e9×RAY) is far above the value-overflow boundary, so `update_borrow_index` returns before clamping is ever relevant — the overflow happens inside `accrue_step` while computing the new totals. `global_sync` is invoked at the top of every pool op path (supply, withdraw, borrow, repay, liquidate, flash), and `update_indexes` itself is a permissionless entrypoint. The harness test `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` (`tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:320-361`) demonstrates the freeze: after the cliff, `try_withdraw_raw` and `try_repay` both revert with `MathOverflow`.

### Impact Explanation
Permanent freezing of funds for the affected market: once `scaled_total × index` crosses `i128::MAX`, every entrypoint that accrues panics deterministically, so suppliers cannot withdraw, borrowers cannot repay, and liquidators cannot seize. There is no admin escape hatch in the accrual path — the panic is in shared `accrue_step` math executed unconditionally by `global_sync`. This matches the accepted impact class "permanent freezing of funds."

### Likelihood Explanation
Reaching the cliff requires a large market (≈ billions of units of a high-decimal token) sustained at high borrow utilization for years so the index compounds ~170× before the cap. An unprivileged attacker cannot fast-forward ledger time, so this is not an on-demand trigger; it is a latent protocol ceiling that any whale-scale market on a steep rate curve eventually reaches. Likelihood is medium-low, but impact is permanent and affects all users of the market — consistent with a Medium/High severity finding rather than a theoretical-only issue, since the harness confirms it empirically rather than hypothetically.

### Recommendation
Make accrual saturating instead of panicking: compute `supplied * index` and `borrowed * index` via `mul_div_floor_saturating`/`mul_ceil` saturating variants, or check `would-overflow` before `Ray::mul` and clamp the index to `MAX_BORROW_INDEX_RAY`/`MAX_SUPPLY_INDEX_RAY` first, so the cap engages before the value ceiling. Alternatively derive the cap as `min(MAX_INDEX, i128::MAX / scaled_total)` per accrual step so the index never grows past what the market's scaled totals can be multiplied by. Add a regression test mirroring `large_positions_and_long_horizons.rs:320` asserting the cap engages instead of reverting.

### Proof of Concept
Existing harness test, `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:320-361`:

```rust
let principal = BILLION * 10i128.pow(18);          // 1e9 tokens, 18 decimals
t.supply_raw(BOB, "BIG18", principal);
let debt = principal / 100 * 98;                   // ~98% utilization
t.supply_raw(ALICE, "COL", BILLION * 10_000_000 * 3);
t.borrow_raw(ALICE, "BIG18", debt);
// advance years; eventually try_update_indexes_for(&["BIG18"]) -> MathOverflow
// with last.borrow_index < MAX_BORROW_INDEX_RAY (cap never engaged)
assert_contract_error(t.try_withdraw_raw(BOB, "BIG18", 1), errors::MATH_OVERFLOW);
assert_contract_error(t.try_repay(ALICE, "BIG18", 1.0), errors::MATH_OVERFLOW);
```

Relevant code:
- `common/src/rates/index.rs:34` — `supplied.mul(env, old_index)` panics on i128 product overflow.
- `common/src/rates/index.rs:80-83` — `borrowed.mul(env, new_borrow_index)` same issue.
- `common/src/rates/index.rs:13-19` — cap applied to the index only, never reached.
- `common/src/constants/pool.rs:19` — `MAX_BORROW_INDEX_RAY = 1e36`, above the overflow boundary for large scaled totals.
- `contracts/pool/src/interest.rs:20-33` — `global_sync` runs accrual before every verb, propagating the panic to all entrypoints.