### Title
Scaled-debt value overflow during accrual permanently freezes a market - (File: common/src/rates/simulate.rs)

### Summary
A sufficiently large borrowed position can push `borrowed * borrow_index` beyond the `i128` range before the configured borrow-index ceiling is reached. Every subsequent pool mutation accrues the market first, so repayment, withdrawal, liquidation, and index maintenance all revert with `MathOverflow`.

### Finding Description
`accrue_step` computes the market’s current debt with `scaled_to_original(borrowed, borrow_index)` before applying the next interest factor or enforcing `MAX_BORROW_INDEX_RAY`. [1](#0-0)  `scaled_to_original` calls `Ray::mul`, which delegates to `mul_div_half_up`. [2](#0-1)  `mul_div_half_up` widens the intermediate product to `I256`, but still panics when the final quotient does not fit into `i128`. [3](#0-2) 

The borrow-index cap is applied to the index itself, not to the product of the index and the scaled debt, so it does not bound the value calculation to `i128::MAX`. [4](#0-3)  Once the market enters this state, `update_indexes` reaches the same accrual path and cannot advance `last_timestamp`. [5](#0-4)  Repayment and withdrawal also call `load_leg`, which loads the market and runs `global_sync` before resolving or mutating the position. [6](#0-5)  The same pre-accrual ordering exists in pool repayment and withdrawal. [7](#0-6) [8](#0-7) 

An unprivileged user can create the prerequisite state through `Controller::supply` and `Controller::borrow` on accounts it owns, then later call the permissionless `Controller::update_indexes`. [9](#0-8) [10](#0-9)  The resulting panic is not merely a rejected transaction: because no mutating path can complete accrual, the market retains the poisoned scaled debt and old timestamp indefinitely.

### Impact Explanation
All supplier funds in the affected `(hub_id, asset)` market become permanently unavailable because withdrawals cannot pass the required accrual step. Borrowers cannot repay and liquidators cannot reduce the unsafe debt, so collateral backing the position is also frozen and the pool cannot recover through normal liquidation or bad-debt processing. Even the owner-gated `update_params` path accrues under the old model before replacing it, so parameter changes do not provide an in-contract recovery path. [11](#0-10) 

### Likelihood Explanation
The attack requires a very large market, high sustained utilization, and enough elapsed accrual for the debt index to make the RAY-denominated debt value exceed `i128::MAX`. Those are demanding prerequisites, but they are reachable through ordinary supply and borrow calls when the listed asset’s decimal domain and caps admit sufficiently large positions. The indexed regression test demonstrates that the overflow occurs before `MAX_BORROW_INDEX_RAY`, and that both repayment and withdrawal subsequently fail with `MathOverflow`. [12](#0-11) 

### Recommendation
Bound index growth by the representable value of the current scaled balances, not only by the fixed index ceiling. Before accrual, compute a per-market maximum index such that `borrowed * borrow_index / RAY` and `supplied * supply_index / RAY` remain within `i128::MAX`, and clamp the new indexes to those limits without calculating the overflowing product. Add an explicit recovery path that can process repayment, liquidation, or bad-debt cleanup without first executing the overflowing accrual, and extend the existing long-horizon test to assert that these exits remain available at the numeric boundary.

### Proof of Concept
The repository already contains a deterministic reproduction in `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap`. [13](#0-12) 

```rust
let principal = BILLION * 10i128.pow(18);
t.supply_raw(BOB, "BIG18", principal);
let debt = principal / 100 * 98;
t.supply_raw(ALICE, "COL", BILLION * 10_000_000 * 3);
t.borrow_raw(ALICE, "BIG18", debt);

loop {
    t.advance_time(YEAR_SECS);
    if let Err(e) = t.try_update_indexes_for(&["BIG18"]) {
        break e;
    }
}
```

The observed failure is `MathOverflow`, while the stored borrow index remains below `MAX_BORROW_INDEX_RAY`. [14](#0-13)  Subsequent `withdraw` and `repay` calls fail with the same error because they both accrue first. [15](#0-14)

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

**File:** common/src/rates/scaling.rs (L14-16)
```rust
pub fn scaled_to_original(env: &Env, scaled: Ray, index: Ray) -> Ray {
    scaled.mul(env, index)
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

**File:** common/src/rates/index.rs (L13-18)
```rust
pub fn update_borrow_index(env: &Env, old_index: Ray, interest_factor: Ray) -> Ray {
    let new_index = old_index.mul(env, interest_factor);
    if new_index.raw() > MAX_BORROW_INDEX_RAY {
        return Ray::from(MAX_BORROW_INDEX_RAY);
    }
    new_index
```

**File:** contracts/pool/src/ops/market.rs (L50-57)
```rust
/// Accrues interest under the old model, commits it, then replaces the interest
/// and flash-loan parameters and validates them against the stored decimals.
pub(crate) fn replace_rate_model(env: &Env, hub_asset: HubAssetKey, model: InterestRateModel) {
    ops::renewed_market(env, &hub_asset).commit();

    let params = storage::write_rate_model(env, &hub_asset, &model);
    params.verify(env);
    events::emit_market_params(env, hub_asset.hub_id, hub_asset.asset, params);
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

**File:** contracts/pool/src/ops/mod.rs (L30-47)
```rust
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
}
```

**File:** contracts/pool/src/ops/repay.rs (L40-45)
```rust
pub(crate) fn accounting(env: &Env, action: &PoolAction) -> RepayOutcome {
    let (mut cache, position) = ops::load_leg(env, action);
    let amount = action.amount;

    let (burned, overpayment) = cache.resolve_repay(amount, position);
    let net_repay = amount
```

**File:** contracts/pool/src/ops/withdraw.rs (L57-65)
```rust
pub(crate) fn accounting(
    env: &Env,
    is_liquidation: bool,
    entry: &PoolWithdrawEntry,
) -> WithdrawOutcome {
    require_nonneg_amount(env, entry.protocol_fee);
    let (mut cache, position) = ops::load_leg(env, &entry.action);

    let (burned, gross_amount) = resolve_close_or_partial(&cache, entry.action.amount, position);
```

**File:** contracts/controller/src/lib.rs (L94-115)
```rust
    fn supply(
        env: Env,
        caller: Address,
        account_id: u64,
        spoke_id: u32,
        assets: Vec<(HubAssetKey, i128)>,
    ) -> u64 {
        positions::process_supply(&env, &caller, account_id, spoke_id, &assets)
    }

    /// Borrows against `account_id`'s collateral, paying `to` or the caller.
    /// Requires owner or delegate authorization and post-borrow solvency.
    #[when_not_paused]
    fn borrow(
        env: Env,
        caller: Address,
        account_id: u64,
        borrows: Vec<(HubAssetKey, i128)>,
        to: Option<Address>,
    ) {
        positions::process_borrow(&env, &caller, account_id, &borrows, to);
    }
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
