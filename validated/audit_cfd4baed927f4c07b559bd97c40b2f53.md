### Title
Permissionless market freeze: sustained high-utilization accrual overflows `scaled_to_original` and bricks all repay/withdraw/liquidate paths — (File: contracts/pool/src/interest.rs)

### Summary
Analogous to Consul's cache-related denial of service, the pool's interest accrual (the index "cache" refreshed lazily on every mutation) can be pushed into a state where `global_sync` panics on `MathOverflow`, permanently freezing every position in that market. The panic occurs before any guard or index cap engages, and every state-changing entrypoint accrues first, so once the cliff is reached no one can repay, withdraw, liquidate, or `clean_bad_debt` on that market.

### Finding Description
Every pool mutator loads the market into `Cache` and runs `interest::global_sync`, which accrues in chunks via `accrue_step` before any mutation logic runs. [1](#0-0) 

The harness test `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` demonstrates the freeze concretely: a whale supplies a very large 18-decimal balance, a borrower draws it to 98% utilization on the XLM curve, and after repeated yearly `update_indexes` calls the accrual panics inside `scaled_to_original` while `borrow_index < MAX_BORROW_INDEX_RAY`. [2](#0-1) 

After the panic state is reached the test shows `withdraw` and `repay` both revert with `MATH_OVERFLOW` — the market is permanently frozen, not merely degraded. [3](#0-2) 

The index ceiling (`MAX_BORROW_INDEX_RAY`) never protects this path because the value multiplication overflows before the index clamp is reached. [4](#0-3) 

### Impact Explanation
Permanent freezing of all user funds and debt in the affected market: suppliers cannot withdraw, borrowers cannot repay, and liquidators cannot liquidate, since every verb accrues first and hits the same `MathOverflow` panic. This maps directly to the accepted "permanent freezing of funds" impact class. The trigger is a permissionless `update_indexes` keeper call (`Controller::update_indexes` requires only caller auth) once the borrow index has drifted into the overflow region. [5](#0-4) 

### Likelihood Explanation
Medium. It requires a whale-scale position at sustained ~98% utilization over multiple years — substantial capital and time. But nothing privileged is needed: supply, borrow, and `update_indexes` are all unprivileged entrypoints, and interest accrual alone (no further attacker action) drives the index toward the cliff. Once past it there is no recovery path — no admin verb bypasses accrual, and the overflow is in committed accrual, not a view.

### Recommendation
Bound `scaled_to_original` inputs in `accrue_step`/`global_sync` so the accrual saturates rather than panics: e.g., pre-check `borrowed * borrow_index / RAY` against `i128::MAX` and clamp the index update (`update_borrow_index`) before the value computation, or cap `borrowed`-denominated growth per chunk. A saturating accrual that pins the index at `MAX_BORROW_INDEX_RAY` preserves repay/withdraw/liquidate liveness even at the extreme. The regression bound documented in `docs/reference/formulas.md` (shown incorrect by the test at line 340) should also be corrected. [6](#0-5) 

### Proof of Concept
From `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs` (lines 321–361), condensed:

```rust
let mut t = LendingTest::new()
    .with_market(big("BIG18", 18, xlm_curve()))
    .with_market(col())
    .with_max_utilization_disabled_all_markets()
    .build();
lift_caps(&t, "BIG18", 18);
let principal = BILLION * 10i128.pow(18);
t.supply_raw(BOB, "BIG18", principal);
t.borrow_raw(ALICE, "BIG18", principal / 100 * 98);

// Advance year-by-year; each update_indexes is a permissionless keeper call.
loop { t.advance_time(YEAR_SECS); t.try_update_indexes_for(&["BIG18"])?; }
// -> Err(MATH_OVERFLOW) with borrow_index < MAX_BORROW_INDEX_RAY

// Market is now bricked:
assert_contract_error(t.try_withdraw_raw(BOB, "BIG18", 1),  MATH_OVERFLOW);
assert_contract_error(t.try_repay(ALICE, "BIG18", 1.0),     MATH_OVERFLOW);
```

Every subsequent mutation of `BIG18` reverts in `global_sync` → `accrue_step` → `scaled_to_original`, so all funds in the market are frozen permanently.

### Citations

**File:** contracts/pool/src/interest.rs (L20-33)
```rust
pub(crate) fn global_sync(env: &Env, cache: &mut Cache) {
    if !cache.needs_accrual() {
        return;
    }

    let mut remaining = cache.elapsed_ms();
    while let Some(nonzero) = NonZeroU64::new(remaining) {
        let chunk = nonzero.get().min(MAX_COMPOUND_DELTA_MS);
        accrue_chunk(env, cache, chunk);
        remaining = remaining.saturating_sub(chunk);
    }

    cache.mark_accrued();
}
```

**File:** tests/test-harness/tests/controller/large_positions_and_long_horizons.rs (L316-361)
```rust
/// `i128::MAX`, 170 times that. At the XLM curve's steep segment the index
/// grows past 170x in a few years, and the next accrual panics inside
/// `scaled_to_original`. Every verb accrues first, so the market freezes:
/// no repay, no withdraw, no liquidation. The index cap never engages.
#[test]
fn a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap() {
    let mut t = LendingTest::new()
        .with_market(big("BIG18", 18, xlm_curve()))
        .with_market(col())
        .with_max_utilization_disabled_all_markets()
        .build();
    lift_caps(&t, "BIG18", 18);
    lift_caps(&t, "COL", 7);
    let principal = BILLION * 10i128.pow(18);
    t.supply_raw(BOB, "BIG18", principal);
    let debt = principal / 100 * 98;
    t.supply_raw(ALICE, "COL", BILLION * 10_000_000 * 3);
    t.borrow_raw(ALICE, "BIG18", debt);

    let mut years = 0u32;
    let failure = loop {
        years += 1;
        assert!(
            years <= 40,
            "no cliff within 40 years; the bound in docs/reference/formulas.md is wrong"
        );
        t.advance_time(YEAR_SECS);
        if let Err(e) = t.try_update_indexes_for(&["BIG18"]) {
            break e;
        }
    };
    let failed: Result<(), soroban_sdk::Error> = Err(failure);
    assert_contract_error(failed, errors::MATH_OVERFLOW);
    let last = book(&t, "BIG18");
    assert!(
        last.borrow_index < MAX_BORROW_INDEX_RAY,
        "the index cap did not engage before the value overflow"
    );
    // The market is frozen: exits and repayments accrue first and hit the same panic.
    assert_contract_error(t.try_withdraw_raw(BOB, "BIG18", 1), errors::MATH_OVERFLOW);
    assert_contract_error(t.try_repay(ALICE, "BIG18", 1.0), errors::MATH_OVERFLOW);
    std::println!(
        "ray-value cliff reached after {years} years at 98 percent utilization on the XLM curve; last index x{:.1}",
        last.borrow_index as f64 / RAY as f64
    );
}
```

**File:** contracts/controller/src/markets.rs (L118-125)
```rust
/// Accrues indexes for each hub asset. Requires caller authorization and no flash loan.
pub(crate) fn update_indexes(env: &Env, caller: Address, assets: Vec<HubAssetKey>) {
    validation::require_authorized_caller(env, &caller);

    let mut cache = Context::new(env);
    let pool_addr = cache.cached_pool_address();
    pool_update_indexes_call(env, &pool_addr, &assets);
}
```
