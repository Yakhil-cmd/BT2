### Title
RAY-valued accrual overflows before the index cap, permanently freezing the market - (File: common/src/rates/simulate.rs)

### Summary
A sufficiently large market can reach an `i128` overflow while calculating its current borrowed or supplied value, even though both indexes remain below their configured ceilings. Because every pool mutation performs accrual before applying the requested operation, the first overflow makes later `withdraw`, `repay`, `liquidate`, `clean_bad_debt`, `recapitalize`, and `update_indexes` attempts fail for that market. The result is permanent freezing of supplier and protocol funds.

### Finding Description
`accrue_step` converts scaled RAY balances back to value with `scaled_to_original` before computing utilization and interest. That helper executes `scaled.mul(env, index)`, which panics when the RAY-valued product exceeds `i128::MAX`. [1](#0-0) [2](#0-1) 

`global_sync` calls `accrue_step` for every elapsed accrual chunk before updating the market timestamp, so a panic aborts the accrual without advancing `last_timestamp`. [3](#0-2)  All ordinary pool mutation legs load a synced market first, meaning the same failing multiplication runs before the intended mutation. [4](#0-3)  The standalone `update_indexes` path follows the same `Cache::load` → `global_sync` sequence. [5](#0-4) 

The repository already contains a reproduction: a one-billion-token, 18-decimal market at 98% utilization reaches the value ceiling while `borrow_index < MAX_BORROW_INDEX_RAY`; subsequent `withdraw` and `repay` both panic with `MathOverflow`. [6](#0-5) 

### Impact Explanation
This permanently freezes all assets held by the affected market. Suppliers cannot withdraw, borrowers cannot repay, liquidators cannot rescue unhealthy accounts, and recapitalization or bad-debt cleanup cannot proceed because each route must first accrue the market. The pool can retain a valid token balance while its accounting layer is unable to operate, leaving user deposits and unclaimed protocol revenue inaccessible.

### Likelihood Explanation
The condition requires a very large token book and enough elapsed high-utilization accrual for an index to multiply the scaled balance beyond `i128::MAX`. That makes the attack capital- and time-dependent rather than immediately reachable on an ordinary market. No privileged action is required to trigger it once such a market exists: any caller can submit controller `update_indexes`, and any user action touching the market reaches the same accrual path. Medium severity is appropriate because the exploit has substantial economic preconditions but causes permanent market-level denial of withdrawals and recovery.

### Recommendation
Do not compute utilization through an unbounded `i128` RAY-value multiplication during accrual. Use a widened `I256`/saturating utilization calculation, or derive utilization from scaled balances in a way that cannot overflow before applying the explicit index ceilings. Additionally, make accrual cap the index when the next value would exceed the representable domain instead of panicking, so risk-reducing operations remain executable after the ceiling is reached.

### Proof of Concept
1. Configure an 18-decimal market and supply `1_000_000_000 * 10^18` base units.
2. Borrow 98% of that liquidity.
3. Advance time in yearly intervals and repeatedly call controller `update_indexes` for the market.
4. Once index growth makes `borrowed * borrow_index` exceed `i128::MAX`, `accrue_step` panics in `scaled_to_original` with `MathOverflow` before the borrow-index cap engages.
5. Subsequent `withdraw`, `repay`, `liquidate`, `clean_bad_debt`, `recapitalize`, and `update_indexes` calls repeat the same accrual and fail, leaving the market frozen. The in-repository reproduction is `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap`. [7](#0-6)

### Citations

**File:** common/src/rates/simulate.rs (L60-66)
```rust
    let borrowed_original = scaled_to_original(env, borrowed, borrow_index);
    let supplied_original = scaled_to_original(env, supplied, supply_index);
    let util = utilization(env, borrowed_original, supplied_original);
    let borrow_rate = calculate_borrow_rate(env, util, params);
    let interest_factor = compound_interest(env, borrow_rate, delta_ms);

    let new_borrow_index = update_borrow_index(env, borrow_index, interest_factor);
```

**File:** common/src/rates/scaling.rs (L12-16)
```rust
/// Converts a scaled `Ray` amount to its original (unscaled) value by
/// multiplying by `index`, rounding half up.
pub fn scaled_to_original(env: &Env, scaled: Ray, index: Ray) -> Ray {
    scaled.mul(env, index)
}
```

**File:** contracts/pool/src/interest.rs (L20-32)
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
```

**File:** contracts/pool/src/ops/mod.rs (L29-46)
```rust
/// Loads a market cache and accrues interest through the current ledger time.
pub(crate) fn synced_market(env: &Env, hub_asset: &HubAssetKey) -> Cache {
    let mut cache = Cache::load(env, hub_asset);
    interest::global_sync(env, &mut cache);
    cache
}

/// Renews instance TTL, then loads and accrues the market.
pub(crate) fn renewed_market(env: &Env, hub_asset: &HubAssetKey) -> Cache {
    renew_instance(env);
    synced_market(env, hub_asset)
}

/// Validates `action.amount ≥ 0`, syncs the market, and returns (cache, scaled position).
pub(crate) fn load_leg(env: &Env, action: &PoolAction) -> (Cache, Ray) {
    require_nonneg_amount(env, action.amount);
    let cache = synced_market(env, &action.hub_asset);
    (cache, Ray::from(action.position.scaled_amount))
```

**File:** contracts/pool/src/ops/market.rs (L65-72)
```rust
pub(crate) fn accrue(env: &Env, hub_assets: Vec<HubAssetKey>) {
    renew_instance(env);

    for hub_asset in hub_assets.iter() {
        let mut cache = Cache::load(env, &hub_asset);
        interest::global_sync(env, &mut cache);
        events::emit_market_state(env, cache.commit());
    }
```

**File:** tests/test-harness/tests/controller/large_positions_and_long_horizons.rs (L315-356)
```rust
/// The cliff. A billion whole tokens is `1e36` raw ray; the value ceiling is
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
```
