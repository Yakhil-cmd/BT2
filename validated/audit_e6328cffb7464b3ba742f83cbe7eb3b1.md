### Title
Interest accrual overflows before index caps, permanently freezing a high-value market - (File: common/src/rates/simulate.rs)

### Summary
An unprivileged user can push a sufficiently large market into a state where every operation that synchronizes that market reverts with `MathOverflow`. The overflow happens while unscaling `borrowed * borrow_index` or `supplied * supply_index` inside `accrue_step`, before the borrow-index ceiling can bound the stored index. [1](#0-0)  Once reached, `update_indexes`, `supply`, `borrow`, `withdraw`, `repay`, liquidation-related pool calls, revenue claims, and recapitalization for that market all fail because they call `global_sync` before mutating state. [2](#0-1) 

### Finding Description
The controller’s permissionless `update_indexes(caller, assets)` entrypoint authorizes `caller` and forwards the supplied `Vec<HubAssetKey>` to the pool. [3](#0-2)  In the pool, `update_indexes` calls `ops::market::accrue`, which loads each market and invokes `interest::global_sync`. [4](#0-3) 

`global_sync` repeatedly invokes `accrue_step` over elapsed-time chunks. [5](#0-4)  Each step first multiplies the RAY-scaled `borrowed` and `supplied` totals by their respective RAY indexes through `scaled_to_original`. [6](#0-5)  That helper performs `scaled.mul(env, index)`, which panics when the product exceeds the representable domain. [7](#0-6) 

The borrow-index cap is applied only after this unscale operation. [8](#0-7)  Consequently, a market can satisfy `borrow_index < MAX_BORROW_INDEX_RAY` while `borrowed * borrow_index` already exceeds `i128::MAX`, preventing every subsequent accrual. [9](#0-8) 

### Impact Explanation
This permanently freezes the affected market: suppliers cannot withdraw, borrowers cannot repay, liquidators cannot settle debt, and governance cannot update the market’s rate parameters because those paths sync the market before proceeding. [2](#0-1)  The existing regression test demonstrates that once the overflow state is reached, `update_indexes`, `withdraw`, and `repay` all revert with `MATH_OVERFLOW`. [10](#0-9)  The result is permanent freezing of user funds in that market, matching an accepted impact class.

### Likelihood Explanation
Reaching the condition requires a very large market and sustained utilization long enough for index growth to make the RAY-scaled product exceed the `i128` domain. [11](#0-10)  A single funded user can establish the state by supplying the target asset, supplying collateral, borrowing the target asset, and later calling `update_indexes` for its `HubAssetKey`; unlike CPU exhaustion, the panic is state-dependent and remains reproducible on every later transaction. [3](#0-2)  The regression test confirms this bound can be reached while the stored index remains below its configured ceiling. [12](#0-11) 

### Recommendation
Enforce supply and borrow caps against worst-case future index growth, not merely current amounts. Specifically:

- Derive maximum scaled `supplied` and `borrowed` values such that `scaled * MAX_SUPPLY_INDEX_RAY` and `scaled * MAX_BORROW_INDEX_RAY` remain safely representable.
- Enforce those limits in all share-minting paths, including ordinary supply/borrow, flash-created debt, protocol revenue shares, share-credit liquidations, and bad-debt collateral reclassification.
- Alternatively, make accrual detect unsafe scaled/index products before unscaling and clamp or quarantine the market without trapping; preserving repay and withdrawal paths should take priority over preserving exact accrual.
- Add a production-level invariant test asserting that `supplied * supply_index` and `borrowed * borrow_index` remain representable for every accepted mutation.

### Proof of Concept
The repository already contains a reproduction in `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs`. [13](#0-12) 

Conceptually, against a market whose configured caps admit the amount:

1. Call `supply` for the target `HubAssetKey` with a large principal such as `1_000_000_000 * 10^18` base units.
2. Supply sufficient collateral and call `borrow` for the same `HubAssetKey` at high utilization.
3. Let accrual time elapse under the market’s rate model.
4. Call `update_indexes(caller, vec![HubAssetKey { hub_id, asset }])`.
5. `global_sync` reaches `accrue_step`, where `scaled_to_original(borrowed, borrow_index)` or `scaled_to_original(supplied, supply_index)` panics with `MathOverflow`.
6. Subsequent `update_indexes`, `withdraw`, and `repay` calls repeat the same synchronization and revert, leaving the market’s cash inaccessible. [14](#0-13)

### Citations

**File:** common/src/rates/simulate.rs (L51-71)
```rust
pub fn accrue_step(
    env: &Env,
    params: &MarketParams,
    borrowed: Ray,
    supplied: Ray,
    borrow_index: Ray,
    supply_index: Ray,
    delta_ms: u64,
) -> AccrualStep {
    let borrowed_original = scaled_to_original(env, borrowed, borrow_index);
    let supplied_original = scaled_to_original(env, supplied, supply_index);
    let util = utilization(env, borrowed_original, supplied_original);
    let borrow_rate = calculate_borrow_rate(env, util, params);
    let interest_factor = compound_interest(env, borrow_rate, delta_ms);

    let new_borrow_index = update_borrow_index(env, borrow_index, interest_factor);

    let (supplier_rewards, protocol_fee) =
        calculate_supplier_rewards(env, params, borrowed, new_borrow_index, borrow_index);

    let new_supply_index = update_supply_index(env, supplied, supply_index, supplier_rewards);
```

**File:** contracts/pool/src/ops/mod.rs (L29-39)
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

**File:** common/src/rates/scaling.rs (L12-16)
```rust
/// Converts a scaled `Ray` amount to its original (unscaled) value by
/// multiplying by `index`, rounding half up.
pub fn scaled_to_original(env: &Env, scaled: Ray, index: Ray) -> Ray {
    scaled.mul(env, index)
}
```

**File:** common/src/rates/index.rs (L11-18)
```rust
/// Applies `interest_factor` to `old_index` to produce the new borrow index,
/// capped at `MAX_BORROW_INDEX_RAY`.
pub fn update_borrow_index(env: &Env, old_index: Ray, interest_factor: Ray) -> Ray {
    let new_index = old_index.mul(env, interest_factor);
    if new_index.raw() > MAX_BORROW_INDEX_RAY {
        return Ray::from(MAX_BORROW_INDEX_RAY);
    }
    new_index
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
