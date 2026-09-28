### Title
Permanent market freeze: borrow-index growth overflows `i128` in `scaled_to_original` before `MAX_BORROW_INDEX_RAY` cap engages — (File: common/src/rates/scaling.rs)

### Summary
The OpenCV CVE is a reachable assertion (input-size check) that DoSes the process. The analog in XOXNO Lending is a reachable arithmetic panic: every pool verb runs `interest::global_sync` first, and accrual multiplies the stored scaled debt by the borrow index via `scaled_to_original` → `Ray::mul`, which panics with `MathOverflow` when `borrowed_scaled * borrow_index` exceeds `i128::MAX`. The borrow-index cap `MAX_BORROW_INDEX_RAY` (1e36 raw = 1e9x) is far above the value ceiling (`i128::MAX` ≈ 170e36 ray), so on a large market the product overflows long before the cap clamps the index. Once crossed, every subsequent accrual panics, permanently freezing the market.

### Finding Description
`accrue_step` in `common/src/rates/simulate.rs` computes:

```text
borrowed_original = scaled_to_original(borrowed, borrow_index)   // line 60
...
new_total_debt   = borrowed.mul(new_borrow_index)                // index.rs:81
```

`scaled_to_original` (`common/src/rates/scaling.rs:14`) is just `scaled.mul(env, index)`, a checked `i128` multiply that panics with `GenericError::MathOverflow` on overflow (`common/src/math/fp_core.rs`). `update_borrow_index` (`common/src/rates/index.rs:13-19`) only clamps at `MAX_BORROW_INDEX_RAY = 1e36` raw (`common/src/constants/pool.rs:19`), i.e. a 1e9× index — but the representable value ceiling is `i128::MAX ≈ 1.7e38` ray. A market holding ~1e36 ray of scaled debt (`max_cap_for_decimals` permits up to ~1.7e29 whole 18-decimal tokens, `common/src/validation.rs:48`) hits the value ceiling at an index of only ~170×, roughly 6 million× below the index cap.

Because `global_sync` (`contracts/pool/src/interest.rs:20-33`) runs at the top of every state mutation and panic aborts the whole transaction, once `borrowed * borrow_index` overflows, `update_indexes`, `withdraw`, `repay`, `liquidate`, `borrow`, `supply`, and `clean_bad_debt` all revert unconditionally on that market. `apply_bad_debt_to_supply_index` only writes down the supply index — the borrow index is monotone, so there is no recovery path.

An unprivileged attacker can seed this: supply a very large amount of a high-decimal asset (caps raised by governance listing already allow ~170 trillion whole tokens; even a listed cap near that bound suffices), post collateral in a second market, borrow ~98% of it to pin utilization on the steep segment of the rate curve (e.g. the XLM curve), and wait. The existing characterization test proves the failure end-to-end: `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` (`tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:320-361`) asserts `MathOverflow` from `update_indexes`, `withdraw`, and `repay`, and explicitly notes "the market is frozen … The index cap never engages."

### Impact Explanation
Permanent freezing of all funds in the affected market: every supplier's deposit and every borrower's collateral backing debt in that market becomes unreachable, and liquidations can never execute. The impact grows with market size — a whale-scale market locks the most TVL. If multiple markets share collateral positions, the frozen debt also blocks those positions' exits in other markets.

### Likelihood Explanation
Requires (a) a listed high-decimal asset with a large cap, (b) an attacker willing to fund a very large supply and over-collateralized borrow, and (c) sustained high utilization so the index compounds ~170× before anyone intervenes. The attacker must lock significant capital and the trigger is slow, but no privileged action is needed beyond the initial listing/cap, and once the state is reached it is irreversible — there is no index write-down for the borrow index.

### Recommendation
Cap the borrow index at a value-domain-aware bound rather than the uniform `MAX_BORROW_INDEX_RAY` — e.g. clamp `interest_factor` so `borrowed_scaled * new_index` stays within `i128`, or store/track accrued debt in a widened representation (`I256`) inside accrual. At minimum, make `calculate_supplier_rewards`/`scaled_to_original` saturate instead of panicking so accrual degrades gracefully and exits remain possible. Alternatively, enforce a market-level invariant `supplied_scaled * MAX_BORROW_INDEX_RAY <= i128::MAX` via much tighter per-decimal caps.

### Proof of Concept
```rust
// tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:320-361
let mut t = LendingTest::new()
    .with_market(big("BIG18", 18, xlm_curve()))
    .with_market(col())
    .with_max_utilization_disabled_all_markets()
    .build();
lift_caps(&t, "BIG18", 18);
lift_caps(&t, "COL", 7);
let principal = BILLION * 10i128.pow(18);
t.supply_raw(BOB, "BIG18", principal);          // unprivileged whale supply
let debt = principal / 100 * 98;
t.supply_raw(ALICE, "COL", BILLION * 10_000_000 * 3);
t.borrow_raw(ALICE, "BIG18", debt);             // ~98% utilization

loop {
    t.advance_time(YEAR_SECS);
    if let Err(e) = t.try_update_indexes_for(&["BIG18"]) { break e; }
}
// update_indexes, withdraw, repay all revert with MathOverflow (#33)
assert_contract_error(t.try_withdraw_raw(BOB, "BIG18", 1), errors::MATH_OVERFLOW);
assert_contract_error(t.try_repay(ALICE, "BIG18", 1.0), errors::MATH_OVERFLOW);
// last borrow_index << MAX_BORROW_INDEX_RAY — the cap never engaged
```

Root cause chain: `interest::global_sync` (`contracts/pool/src/interest.rs:20`) → `accrue_step` (`common/src/rates/simulate.rs:60`) → `scaled_to_original` = `scaled.mul(index)` (`common/src/rates/scaling.rs:14-15`) → `MathOverflow` panic in `fp_core` — with the effective ceiling set by `i128::MAX`, not by `MAX_BORROW_INDEX_RAY` (`common/src/constants/pool.rs:19`).

Uncertainty: the needed capitalization (~10³⁶ raw units of an 18-decimal asset, i.e. ~1 billion whole tokens) is only reachable if governance lists such an asset with a near-maximal cap; for realistic 7-decimal assets the cliff needs ~170× more index growth and the existing tests show 7-decimal markets survive the tested horizons (`one_billion_at_seven_decimals_accrues_and_exits_on_the_xlm_curve`). So severity is conditional on listed asset decimals/caps and curve steepness — but where reachable, the freeze is permanent and affects all users of the market.