### Title
RAY-scaled market totals overflow before the borrow-index cap, permanently freezing the market - (`File: common/src/rates/simulate.rs`) [1](#0-0) 

### Summary
Interest accrual computes `borrowed * borrow_index` as an `i128` RAY value before the `borrow_index` ceiling can prevent further processing. [2](#0-1) [3](#0-2)  Once the scaled debt and index grow large enough that their product no longer fits `i128`, `scaled_to_original` panics with `MathOverflow`. [4](#0-3) [5](#0-4) 

### Finding Description
Every accrual step first unscales the outstanding borrow and supply values with `scaled_to_original`, and only afterwards computes the rate, updates the borrow index, and clamps it to `MAX_BORROW_INDEX_RAY`. [6](#0-5)  The index cap therefore protects the stored index but does not bound the pre-clamp value multiplication used to calculate utilization. [3](#0-2) 

The strongest permissionless trigger is `Controller::update_indexes(hub_assets=[target_market])`, which forwards to `LiquidityPool::update_indexes`. [7](#0-6) [8](#0-7)  The pool implementation invokes `global_sync` for the target market, while all regular market mutations use the same synchronization path before changing state. [9](#0-8) [10](#0-9) 

### Impact Explanation
Once the market crosses the `i128` RAY-value ceiling, every subsequent accrual reverts before `last_timestamp` is committed, making the condition permanent rather than recoverable by waiting or resubmitting. [11](#0-10)  Because market mutations synchronize first, suppliers cannot withdraw, borrowers cannot repay, liquidations cannot settle the affected debt, and permissionless bad-debt cleanup or recapitalization paths that touch the market also remain blocked. [12](#0-11) 

The repository’s boundary test demonstrates this exact outcome: an 18-decimal market containing one billion whole tokens and 98% utilization eventually fails `update_indexes` with `MathOverflow`, and subsequent `withdraw` and `repay` calls fail identically. [13](#0-12) 

### Likelihood Explanation
The prerequisite is an extremely large market whose scaled debt times its accrued index exceeds `i128::MAX`; the checked arithmetic deliberately rejects the result, so this is a reachable numeric boundary rather than memory corruption. [14](#0-13)  High sustained utilization accelerates index growth, but the overflow can arise from ordinary deposits and borrows on an admitted market without privileged input at trigger time. [9](#0-8)  The capital requirement limits immediate exploitation, while any market that organically approaches the boundary can be frozen permanently by one permissionless accrual call. [15](#0-14) 

### Recommendation
Bound market share totals and accrued index values so every product consumed by accrual remains representable before relying on the index ceiling. [1](#0-0)  In particular, reject or pause supply and borrow growth that would make `borrowed * MAX_BORROW_INDEX_RAY` or `supplied * MAX_SUPPLY_INDEX_RAY` exceed `i128::MAX`, and cap utilization/index progression before evaluating utilization. [2](#0-1) [16](#0-15)  Alternatively, make utilization and reward calculations use saturating or widened intermediate values consistently and clamp the resulting state without aborting accrual. [17](#0-16) 

### Proof of Concept
1. On an admitted 18-decimal market, supply approximately `1_000_000_000 * 10^18` base units and establish debt at 98% utilization from a sufficiently collateralized position. [18](#0-17) 
2. Allow accrual to advance until `borrowed * borrow_index` no longer fits `i128`; the repository test detects the crossing before the stored index reaches `MAX_BORROW_INDEX_RAY`. [19](#0-18) 
3. Call `Controller::update_indexes` with the affected `HubAssetKey`; the controller forwards to the pool and `global_sync` panics in `scaled_to_original`. [7](#0-6) [20](#0-19) 
4. Subsequent `withdraw(account_id, withdrawals=[(affected_market, 1)])` and `repay(account_id, payments=[(affected_market, amount)])` calls fail with `MathOverflow`, as demonstrated by the existing test. [21](#0-20)

### Citations

**File:** common/src/rates/simulate.rs (L60-67)
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

**File:** common/src/rates/index.rs (L13-18)
```rust
pub fn update_borrow_index(env: &Env, old_index: Ray, interest_factor: Ray) -> Ray {
    let new_index = old_index.mul(env, interest_factor);
    if new_index.raw() > MAX_BORROW_INDEX_RAY {
        return Ray::from(MAX_BORROW_INDEX_RAY);
    }
    new_index
```

**File:** common/src/rates/index.rs (L29-44)
```rust
pub fn update_supply_index(env: &Env, supplied: Ray, old_index: Ray, rewards_increase: Ray) -> Ray {
    if supplied == Ray::ZERO || rewards_increase == Ray::ZERO {
        return old_index;
    }

    let total_supplied_value = supplied.mul(env, old_index);

    if total_supplied_value == Ray::ZERO {
        return old_index;
    }

    let new_value = total_supplied_value.checked_add(env, rewards_increase);
    let grown = fp_core::mul_div_floor_saturating(env, new_value.raw(), RAY, supplied.raw());

    let bounded_old = old_index.raw().min(MAX_SUPPLY_INDEX_RAY);
    Ray::from(grown.min(MAX_SUPPLY_INDEX_RAY).max(bounded_old))
```

**File:** common/src/math/fp.rs (L49-52)
```rust
    /// Multiplies two ray values, rounding the result half up.
    pub fn mul(self, env: &Env, other: Ray) -> Ray {
        Ray(fp_core::mul_div_half_up(env, self.0, other.0, RAY))
    }
```

**File:** common/src/math/fp_core.rs (L14-20)
```rust
/// Widens `x`, `y`, and `d` to `I256` for overflow-safe intermediate arithmetic.
fn to_i256_operands(env: &Env, x: i128, y: i128, d: i128) -> (I256, I256, I256) {
    (
        I256::from_i128(env, x),
        I256::from_i128(env, y),
        I256::from_i128(env, d),
    )
```

**File:** common/src/math/fp_core.rs (L116-118)
```rust
    try_mul_div_half_up(env, x, y, d)
        .unwrap_or_else(|| panic_with_error!(env, GenericError::MathOverflow))
}
```

**File:** common/src/math/fp_core.rs (L138-143)
```rust
    let (x256, y256, d256) = to_i256_operands(env, x, y, d);
    x256.mul(&y256)
        .add(&I256::from_i128(env, half))
        .div(&d256)
        .to_i128()
}
```

**File:** contracts/controller/src/external/pool.rs (L109-115)
```rust
/// Accrues and persists market indexes through the current ledger time.
pub(crate) fn pool_update_indexes_call(
    env: &Env,
    pool_addr: &Address,
    hub_assets: &Vec<HubAssetKey>,
) {
    LiquidityPoolClient::new(env, pool_addr).update_indexes(hub_assets)
```

**File:** contracts/pool/src/lib.rs (L174-179)
```rust
    /// Accrues interest for each market in `hub_assets` through the current
    /// ledger time. Commits state even with no elapsed time to reserve the write
    /// footprint, and emits its market state event. Restricted to the owner.
    #[only_owner]
    fn update_indexes(env: Env, hub_assets: Vec<HubAssetKey>) {
        ops::market::accrue(&env, hub_assets);
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

**File:** contracts/pool/src/interest.rs (L25-32)
```rust
    let mut remaining = cache.elapsed_ms();
    while let Some(nonzero) = NonZeroU64::new(remaining) {
        let chunk = nonzero.get().min(MAX_COMPOUND_DELTA_MS);
        accrue_chunk(env, cache, chunk);
        remaining = remaining.saturating_sub(chunk);
    }

    cache.mark_accrued();
```

**File:** tests/test-harness/tests/controller/large_positions_and_long_horizons.rs (L315-321)
```rust
/// The cliff. A billion whole tokens is `1e36` raw ray; the value ceiling is
/// `i128::MAX`, 170 times that. At the XLM curve's steep segment the index
/// grows past 170x in a few years, and the next accrual panics inside
/// `scaled_to_original`. Every verb accrues first, so the market freezes:
/// no repay, no withdraw, no liquidation. The index cap never engages.
#[test]
fn a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap() {
```

**File:** tests/test-harness/tests/controller/large_positions_and_long_horizons.rs (L329-356)
```rust
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
