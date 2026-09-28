### Title
Panic in `scaled_to_original` during interest accrual permanently freezes a whale-scale market — all repay/withdraw/liquidate paths abort with `MathOverflow` - (File: contracts/pool/src/cache/scale.rs)

### Summary
CVE-2019-5008 is a NULL-deref crash causing denial of service. The direct analog in XOXNO Lending's Soroban code is a reachable panic (contract abort) in the pool's fixed-point accrual path: `Cache::calculate_utilization` calls `scaled_to_original(&self.env, self.borrowed, self.borrow_index)`, which panics with `GenericError::MathOverflow` when the i128 product exceeds `i128::MAX`. Every state-changing pool op accrues first, so once a market's scaled-debt × borrow-index product reaches the RAY value ceiling, that market is permanently frozen — no repay, no withdraw, no liquidation — while the `MAX_BORROW_INDEX_RAY` index cap that should have stopped accrual never engages.

### Finding Description
`contracts/pool/src/cache/scale.rs:23` unscales the market's scaled borrow shares by the borrow index inside `calculate_utilization`, which runs as part of accrual before every operation (`withdraw`, `repay`, `liquidate`, `update_indexes`, flash and strategy legs all flow through the same `Cache` construction). `scaled_to_original` performs the `scaled * index` multiply in i128 and panics on overflow (`MathOverflow`, see `common/src/errors.rs` and the checked-arithmetic pattern in `contracts/controller/src/storage/protocol.rs:167-169`).

The codebase's own test `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` (`tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:321-360`) proves the failure: a billion-token market (18 decimals → ~1e36 raw RAY) at ~98% utilization on the steep XLM rate curve grows the borrow index past ~170× within a few years, at which point `scaled * index` overflows i128 before the index reaches `MAX_BORROW_INDEX_RAY`. The test then asserts:

- `try_update_indexes_for(["BIG18"])` fails with `MATH_OVERFLOW`
- `try_withdraw_raw(BOB, "BIG18", 1)` fails with `MATH_OVERFLOW`
- `try_repay(ALICE, "BIG18", 1.0)` fails with `MATH_OVERFLOW`
- `last.borrow_index < MAX_BORROW_INDEX_RAY` — the cap meant to bound the index never engages.

Because the panic happens inside accrual, which runs before any verb-specific logic, there is no ordering workaround: no entrypoint can mutate that market again, including liquidation of the underwater borrowers that drove it there and `recapitalize`/`clean_bad_debt` paths that would write the debt down.

### Impact Explanation
Permanent freezing of all funds in the affected (hub, token) market book. Suppliers can never withdraw; borrowers can never repay; liquidators can never seize collateral backing the debt. On a real (e.g. USDC-class) pool this is a total loss of the market's TVL — every depositor's balance is locked forever. This satisfies the accepted impact class "permanent freezing of funds" / "contract unable to operate."

### Likelihood Explanation
Reachability is demonstrated, not hypothetical: permissionless `controller::update_indexes` is exactly the call that trips the panic, and any `supply`/`borrow`/`repay`/`withdraw`/`liquidate` touching the market does the same. The preconditions are demanding — a market holding on the order of 10^9 whole tokens at ~18 decimals, caps lifted or a high-decimal asset, and sustained ~98% utilization on the steep end of the rate curve for years — so it cannot be triggered quickly by a lone attacker on a small market. However, utilization near 100% is achievable by ordinary borrowers refusing to repay, `max_utilization` enforcement does not prevent it (the test disables it, but even with it, utilization climbs to the cap), and once the product crosses the i128 ceiling there is no recovery path — the index cap is dead code relative to this overflow. Severity is High: catastrophic impact, plausible-but-slow trigger.

### Recommendation
Enforce `MAX_BORROW_INDEX_RAY` (and a supply-index equivalent) *before* the value multiply — i.e., compute the new index, clamp it to the cap, and only then unscale. Alternatively, perform the index growth and the `scaled * index` multiply in a wider type (or `checked_mul` with saturation to the capped index) so accrual can never abort. Ordering matters: the cap must engage at index-update time, not after a multiplication that already overflowed, otherwise every verb that accrues remains a permanent abort.

### Proof of Concept
The in-repo test at `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:321-360` is a complete PoC:

```rust
let mut t = LendingTest::new()
    .with_market(big("BIG18", 18, xlm_curve()))
    .with_market(col())
    .with_max_utilization_disabled_all_markets()
    .build();
lift_caps(&t, "BIG18", 18);
lift_caps(&t, "COL", 7);
let principal = BILLION * 10i128.pow(18);
t.supply_raw(BOB, "BIG18", principal);          // unprivileged supply
let debt = principal / 100 * 98;
t.supply_raw(ALICE, "COL", BILLION * 10_000_000 * 3);
t.borrow_raw(ALICE, "BIG18", debt);             // unprivileged borrow → ~98% util
loop {
    t.advance_time(YEAR_SECS);
    if let Err(e) = t.try_update_indexes_for(&["BIG18"]) { break e; }  // permissionless accrue → panic
}
assert_contract_error(t.try_withdraw_raw(BOB, "BIG18", 1), errors::MATH_OVERFLOW); // frozen
assert_contract_error(t.try_repay(ALICE, "BIG18", 1.0), errors::MATH_OVERFLOW);    // frozen
assert!(book(&t, "BIG18").borrow_index < MAX_BORROW_INDEX_RAY);                    // cap never engaged
```

After the first `MATH_OVERFLOW`, every subsequent call touching that market aborts at `contracts/pool/src/cache/scale.rs:23` — an attacker-reachable, permanent denial of service with all market funds locked.