### Title
Unchecked `i128` RAY-value overflow during accrual can permanently freeze a market - (File: common/src/rates/simulate.rs)

### Summary
An unprivileged caller can eventually place a sufficiently large high-utilization market into a state where every subsequent accrual panics with `MathOverflow`. The pool computes total borrowed and supplied RAY values before applying the borrow-index ceiling, so `borrowed * borrow_index / RAY` can exceed `i128::MAX` while the index itself remains below `MAX_BORROW_INDEX_RAY`. Because all market mutations synchronize interest before proceeding, the affected market can no longer repay, withdraw, liquidate, or update indexes.

### Finding Description
`Controller::update_indexes(caller, assets)` is permissionless and only requires the caller's authorization before forwarding the selected `HubAssetKey` batch to the pool. [1](#0-0) [2](#0-1) 

Pool market operations load the cache and call `interest::global_sync` before mutating state. [3](#0-2)  `global_sync` invokes `accrue_step` for each elapsed chunk. [4](#0-3) 

The vulnerable ordering is in `accrue_step`: it first materializes `scaled_to_original(borrowed, borrow_index)` and `scaled_to_original(supplied, supply_index)`, then calculates utilization, the next borrow index, rewards, and the next supply index. [5](#0-4)  The borrow-index ceiling is applied only inside `update_borrow_index`, after those already-accrued totals have been computed. [6](#0-5) 

Consequently, the configured index ceiling does not bound the pre-clamp debt-value multiplication. When `borrowed * borrow_index / RAY` no longer fits in `i128`, `scaled_to_original` panics before `update_borrow_index` can clamp the index. The accrual is atomic, so the panic also prevents `last_timestamp` from advancing; every later call repeats the same overflowing computation. [7](#0-6) 

### Impact Explanation
This permanently freezes user funds and protocol operations for the affected market. Suppliers cannot withdraw, borrowers cannot repay, liquidators cannot liquidate, and even the permissionless `update_indexes` path cannot advance the market once the accrued debt value crosses the representable `i128` boundary.

The repository's long-horizon test demonstrates the concrete terminal state: after the failing accrual, both `withdraw` and `repay` fail with `MATH_OVERFLOW`, while the stored borrow index remains below `MAX_BORROW_INDEX_RAY`, proving that the value multiplication fails before the intended index cap engages. [8](#0-7) 

### Likelihood Explanation
Reaching the condition requires an unusually large scaled debt and sustained high utilization so that `borrowed * borrow_index / RAY` exceeds `i128::MAX`. An attacker can work toward that state using ordinary `supply`, `borrow`, and `update_indexes` operations, but governance-configured supply/borrow caps, available token liquidity, collateral requirements, and market-rate configuration determine whether a particular deployed market has sufficient headroom.

The existing test constructs the condition with a one-billion-unit, 18-decimal market at approximately 98% utilization and shows that the overflow occurs before the borrow-index ceiling. [9](#0-8)  This is therefore not a general input-validation panic reachable on every market, but once the threshold is crossed the freeze is persistent and cannot be cleared by another unprivileged transaction.

### Recommendation
Do not materialize potentially unbounded RAY asset totals as `i128` before enforcing the index bound. At minimum:

- Enforce a scaled-debt ceiling derived from the current borrow index, such as requiring `borrowed * borrow_index / RAY <= i128::MAX`, before admitting additional debt.
- Handle the borrow-index cap before computing utilization when the unscaled debt cannot be represented.
- Prefer ratio arithmetic that compares `borrowed * borrow_index` with `supplied * supply_index` in `I256`, or otherwise reduces the expression before converting to `i128`.
- Add a production-level regression around a market where `borrowed * borrow_index / RAY > i128::MAX`, asserting that accrual safely clamps instead of permanently panicking.

### Proof of Concept
The existing scenario in `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs` is the direct proof:

```rust
let principal = BILLION * 10i128.pow(18);
t.supply_raw(BOB, "BIG18", principal);
let debt = principal / 100 * 98;
t.supply_raw(ALICE, "COL", BILLION * 10_000_000 * 3);
t.borrow_raw(ALICE, "BIG18", debt);

// Advance ledger time until accrual reaches the unrepresentable
// borrowed-value boundary.
let failure = t.try_update_indexes_for(&["BIG18"]).unwrap_err();

// The stored index is still below MAX_BORROW_INDEX_RAY, but every
// later synchronized operation repeats the same overflowing product.
assert_contract_error(failure, errors::MATH_OVERFLOW);
assert_contract_error(
    t.try_withdraw_raw(BOB, "BIG18", 1),
    errors::MATH_OVERFLOW,
);
assert_contract_error(
    t.try_repay(ALICE, "BIG18", 1.0),
    errors::MATH_OVERFLOW,
);
```

The triggering on-chain path is `Controller::update_indexes(caller, assets)` with `assets = vec![HubAssetKey { hub_id, asset: vulnerable_asset }]`; the same panic then occurs through `synced_market` on `withdraw`, `repay`, and other market mutations. [2](#0-1) [10](#0-9) [11](#0-10)

### Citations

**File:** contracts/controller/src/lib.rs (L367-372)
```rust
    /// Accrues pool borrow and supply indexes for `assets`. Permissionless;
    /// requires caller authorization.
    #[when_not_paused]
    fn update_indexes(env: Env, caller: Address, assets: Vec<HubAssetKey>) {
        markets::update_indexes(&env, caller, assets);
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

**File:** contracts/pool/src/ops/mod.rs (L29-45)
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
```

**File:** contracts/pool/src/interest.rs (L20-48)
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

/// Applies one compound step of `delta_ms` to indexes and protocol revenue.
///
/// The arithmetic lives in [`accrue_step`], shared with the read-only
/// `simulate_update_indexes` so the view and the mutator cannot drift.
fn accrue_chunk(env: &Env, cache: &mut Cache, delta_ms: u64) {
    let step = accrue_step(
        env,
        cache.params(),
        cache.borrowed(),
        cache.supplied(),
        cache.borrow_index(),
        cache.supply_index(),
        delta_ms,
    );
```

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

**File:** common/src/rates/index.rs (L13-18)
```rust
pub fn update_borrow_index(env: &Env, old_index: Ray, interest_factor: Ray) -> Ray {
    let new_index = old_index.mul(env, interest_factor);
    if new_index.raw() > MAX_BORROW_INDEX_RAY {
        return Ray::from(MAX_BORROW_INDEX_RAY);
    }
    new_index
```

**File:** tests/test-harness/tests/controller/large_positions_and_long_horizons.rs (L321-356)
```rust
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
