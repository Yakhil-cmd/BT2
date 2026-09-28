### Title
RAY index-value overflow permanently freezes a heavily borrowed market - ([File: common/src/rates/simulate.rs])

### Summary
An unprivileged user can establish an extremely large supplied and borrowed position in a market whose configured caps and interest curve permit it. After sufficient interest accrual, the next `update_indexes` or any operation touching that market panics while computing `borrowed * borrow_index`, before the borrow index can be clamped at `MAX_BORROW_INDEX_RAY`. Because every pool mutation synchronizes the market first, the panic blocks repayment, withdrawal, liquidation, bad-debt cleanup, and further index updates. [1](#0-0) [2](#0-1) 

### Finding Description
`accrue_step` first computes `borrowed_original = scaled_to_original(borrowed, borrow_index)` and `supplied_original = scaled_to_original(supplied, supply_index)` before updating the index. [3](#0-2)  `scaled_to_original` is an exact RAY multiplication that panics with `MathOverflow` when the resulting RAY-denominated market value cannot fit in `i128`. [4](#0-3) [5](#0-4) 

The borrow index cap is applied only after `accrue_step` has already computed the old scaled debt value. [6](#0-5) [7](#0-6)  Therefore, a sufficiently large `borrowed` share balance can make `borrowed * borrow_index` overflow while `borrow_index` remains far below `MAX_BORROW_INDEX_RAY`. [8](#0-7) 

`global_sync` calls `accrue_step` for each elapsed accrual chunk and never catches the overflow. [9](#0-8)  All pool mutations load a synced market through `synced_market` or `load_leg`, while `update_indexes` calls `global_sync` directly through `ops::market::accrue`. [2](#0-1) [10](#0-9)  The permissionless controller `update_indexes` endpoint forwards the caller-selected market list to the pool. [11](#0-10) [12](#0-11) 

### Impact Explanation
Once the market crosses the `i128` RAY-value boundary, every subsequent pool operation that touches it reverts during mandatory accrual. Suppliers cannot withdraw, borrowers cannot repay, liquidators cannot liquidate debt in the frozen market, and `clean_bad_debt` cannot settle positions there because the underlying seizure/accounting calls synchronize the market first. [2](#0-1) [10](#0-9) 

This permanently freezes the affected market’s funds absent contract intervention. The in-tree regression test demonstrates the exact terminal state: `update_indexes`, `withdraw`, and `repay` all return `MathOverflow`, with the borrow index still below its cap. [13](#0-12) 

### Likelihood Explanation
The attack requires exceptional capital and a market configuration that allows both the required cap and a steep enough borrow-rate curve. The demonstrated configuration uses an allowed maximum borrow rate below `MAX_BORROW_RATE_RAY`, disabled utilization limits, and caps lifted to `max_cap_for_decimals`. [14](#0-13) [15](#0-14) 

The caller-facing actions needed to create the state are ordinary `supply` and `borrow`; time then drives the market over the boundary, and the permissionless `update_indexes` call exposes the freeze. No privileged call, leaked key, malicious token behavior, oracle manipulation, callback, or external service is required. The required scale and elapsed time make this a Medium-severity market availability issue rather than an immediate protocol-wide DoS. [16](#0-15) 

### Recommendation
Bound the scaled principal before multiplying it by an index. In particular:

- Make `scaled_to_original` use a saturating or explicitly capped value where a market-wide total is only needed for utilization.
- Check `borrowed.raw() <= i128::MAX / borrow_index.raw()` before `borrowed.mul(borrow_index)` in `accrue_step`.
- Clamp or refuse the accrual before computing an unrepresentable RAY value, rather than letting `MathOverflow` become a persistent state poison.
- Enforce dynamic supply/borrow caps that account for the maximum possible index multiple, not merely the current index.
- Add a recovery path that can reduce `borrowed` shares or reset market state without first running the overflowing accrual.

The important invariant is `scaled_shares * MAX_*_INDEX_RAY / RAY <= i128::MAX`; the current index caps alone do not enforce that bound. [7](#0-6) [8](#0-7) 

### Proof of Concept
The repository contains an executable reproduction in `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs`:

1. Configure an 18-decimal market with `xlm_curve`, whose `max_borrow_rate` is `1.75 * RAY`.
2. Lift the supply and borrow caps to `max_cap_for_decimals(18)`.
3. Supply `1_000_000_000 * 10^18` units of `BIG18`.
4. Borrow `98%` of that supply using separately supplied collateral.
5. Advance time and repeatedly invoke permissionless `update_indexes`.
6. The next accrual returns `MathOverflow`; `withdraw` and `repay` subsequently fail with the same error while `borrow_index < MAX_BORROW_INDEX_RAY`. [17](#0-16) 

The same sequence can be submitted by one unprivileged address through controller `supply`, `borrow`, and `update_indexes`; the test splits liquidity and collateral across test identities only for readability. [18](#0-17) [11](#0-10)

### Citations

**File:** common/src/rates/simulate.rs (L51-68)
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

**File:** common/src/rates/scaling.rs (L12-16)
```rust
/// Converts a scaled `Ray` amount to its original (unscaled) value by
/// multiplying by `index`, rounding half up.
pub fn scaled_to_original(env: &Env, scaled: Ray, index: Ray) -> Ray {
    scaled.mul(env, index)
}
```

**File:** common/src/math/fp.rs (L12-16)
```rust
/// Adds two raw values, panicking with `GenericError::MathOverflow` on overflow.
fn checked_add_raw(env: &Env, a: i128, b: i128) -> i128 {
    a.checked_add(b)
        .unwrap_or_else(|| panic_with_error!(env, GenericError::MathOverflow))
}
```

**File:** common/src/rates/index.rs (L11-19)
```rust
/// Applies `interest_factor` to `old_index` to produce the new borrow index,
/// capped at `MAX_BORROW_INDEX_RAY`.
pub fn update_borrow_index(env: &Env, old_index: Ray, interest_factor: Ray) -> Ray {
    let new_index = old_index.mul(env, interest_factor);
    if new_index.raw() > MAX_BORROW_INDEX_RAY {
        return Ray::from(MAX_BORROW_INDEX_RAY);
    }
    new_index
}
```

**File:** common/src/constants/pool.rs (L18-23)
```rust
/// Ceiling the borrow index is clamped to after growth, in raw ray units.
pub const MAX_BORROW_INDEX_RAY: i128 = 1_000_000_000_000_000_000_000_000_000_000_000_000;

/// Ceiling the supply index is clamped to after growth, in raw ray units.
/// Equal to [`MAX_BORROW_INDEX_RAY`].
pub const MAX_SUPPLY_INDEX_RAY: i128 = MAX_BORROW_INDEX_RAY;
```

**File:** contracts/pool/src/interest.rs (L20-40)
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

**File:** contracts/controller/src/lib.rs (L73-78)
```rust
    val = "https://github.com/xoxno/rs-lending-xlm"
);

#[contract]
pub struct Controller;

```

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

**File:** tests/test-harness/tests/controller/large_positions_and_long_horizons.rs (L26-38)
```rust
/// Steep XLM stress curve: 175 percent max borrow rate, optimal at 75 percent.
fn xlm_curve() -> MarketParamsPreset {
    MarketParamsPreset {
        max_borrow_rate: RAY * 175 / 100,
        base_borrow_rate: RAY / 100,
        slope1: RAY * 4 / 100,
        slope2: RAY * 10 / 100,
        slope3: RAY * 150 / 100,
        mid_utilization: RAY * 50 / 100,
        optimal_utilization: RAY * 75 / 100,
        max_utilization: RAY,
        reserve_factor: 2000,
    }
```

**File:** tests/test-harness/tests/controller/large_positions_and_long_horizons.rs (L81-95)
```rust
fn lift_caps(t: &LendingTest, asset: &str, decimals: u32) {
    let cap = max_cap_for_decimals(decimals);
    let cfg = t.get_asset_config(asset);
    t.edit_asset_in_spoke_caps(
        asset,
        HARNESS_SPOKE,
        true,
        true,
        cfg.loan_to_value,
        cfg.liquidation_threshold,
        cfg.liquidation_bonus,
        cap,
        cap,
    );
}
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
