### Title
Borrow-index accrual overflows before its cap and permanently freezes a market - (File: common/src/rates/index.rs)

### Summary
A permissionless `update_indexes` call can push a sufficiently large, heavily borrowed market into an `i128` overflow during reward calculation. Because every pool operation synchronizes interest before mutating state, the same panic then blocks withdrawals, repayments, liquidations, new supply, and further accrual for that market.

### Finding Description
`global_sync` splits elapsed time into bounded chunks and calls `accrue_chunk` for each market. `accrue_chunk` delegates index growth and reward calculation to `accrue_step`, which uses `calculate_supplier_rewards` to multiply total scaled debt by both the old and new borrow indexes. [1](#0-0) [2](#0-1) 

`update_borrow_index` clamps only the index itself at `MAX_BORROW_INDEX_RAY`; it does not bound `borrowed * index` to `i128::MAX`. [3](#0-2)  Consequently, `borrowed.mul(old_borrow_index)` or `borrowed.mul(new_borrow_index)` can overflow before the index reaches its nominal ceiling. [4](#0-3)  `scaled_to_original` performs the same unchecked scaled-value multiplication, while every pool mutation first calls `synced_market`, which invokes `global_sync`. [5](#0-4) [6](#0-5) 

The permissionless `controller::update_indexes(caller, hub_assets)` path reaches the pool accrual loop for each supplied `HubAssetKey`; the pool calls `Cache::load`, `interest::global_sync`, and `cache.commit`. [7](#0-6)  The regression test constructs an 18-decimal market with one billion whole units and 98% utilization, then confirms that accrual fails with `MATH_OVERFLOW` while `borrow_index` remains below `MAX_BORROW_INDEX_RAY`. [8](#0-7) 

### Impact Explanation
After the overflow state is reached, withdrawal and repayment calls revert because their pool paths accrue before processing the requested operation. [6](#0-5)  The regression test explicitly confirms that both a supplier withdrawal and a borrower repayment panic with `MATH_OVERFLOW`. [9](#0-8) 

This permanently freezes supplier funds and prevents borrowers from reducing debt; liquidation cannot bypass the panic because liquidation repayment and seizure legs also load synchronized pool markets. [10](#0-9)  Unless a privileged upgrade or administrative intervention exists, the market remains unable to operate.

### Likelihood Explanation
Triggering this state requires a very large market denominator in scaled RAY terms, substantial outstanding debt, and sustained utilization on an interest-rate curve that can grow the index enough for `borrowed * index` to exceed `i128::MAX`. The test scenario uses a one-billion-token, 18-decimal market at 98% utilization and governance-configured caps/utilization limits that permit that scale. [11](#0-10) 

The final accrual itself is permissionless, but the economically extreme preconditions make this a Medium-severity availability issue rather than an easily repeated exploit. Existing configured caps may prevent the state in some deployments; the defect is that the index cap is applied to the wrong quantity and therefore cannot guarantee the scaled-value arithmetic stays in range.

### Recommendation
Bound the scaled total-debt product before multiplying, not just the index after growth. Compute a market-specific maximum index as approximately `i128::MAX / borrowed.raw()` and clamp `new_borrow_index` to the lesser of that bound and `MAX_BORROW_INDEX_RAY`, using saturating or checked arithmetic. Apply the same product-domain check to supply-side value growth and add regression coverage for the point where scaled totals approach `i128::MAX`. [12](#0-11) 

### Proof of Concept
1. Create a valid 18-decimal market whose configured supply, borrow, and utilization limits permit approximately `1e27` supplied base units.
2. Supplier BOB calls `controller.supply` for `BIG18` with `1_000_000_000 * 10^18` base units.
3. Borrower ALICE supplies sufficient collateral and calls `controller.borrow` for 98% of the supplied `BIG18`.
4. Allow interest to accrue at sustained high utilization until the next accrual would make `borrowed * borrow_index` exceed `i128::MAX`.
5. Any address calls `controller.update_indexes(caller, vec![(hub_id, BIG18)])`; the pool reaches `calculate_supplier_rewards`, where one of the scaled-debt multiplications overflows and reverts with `MATH_OVERFLOW`. [13](#0-12) [4](#0-3) 
6. `controller.withdraw` for BOB and `controller.repay` for ALICE subsequently revert with the same error because both load a synced market before mutating it. [9](#0-8)

### Citations

**File:** contracts/pool/src/interest.rs (L20-52)
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

    cache.set_borrow_index(step.borrow_index);
    cache.set_supply_index(step.supply_index);
    cache.accrue_revenue(step.revenue_shares);
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

**File:** common/src/rates/index.rs (L29-45)
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
}
```

**File:** common/src/rates/index.rs (L73-88)
```rust
pub fn calculate_supplier_rewards(
    env: &Env,
    params: &MarketParams,
    borrowed: Ray,
    new_borrow_index: Ray,
    old_borrow_index: Ray,
) -> (Ray, Ray) {
    let old_total_debt = borrowed.mul(env, old_borrow_index);
    let new_total_debt = borrowed.mul(env, new_borrow_index);

    let accrued_interest = new_total_debt.checked_sub(env, old_total_debt);

    let protocol_fee = params.reserve_factor.apply_to_ray(env, accrued_interest);
    let supplier_rewards = accrued_interest.checked_sub(env, protocol_fee);

    (supplier_rewards, protocol_fee)
```

**File:** common/src/rates/scaling.rs (L12-16)
```rust
/// Converts a scaled `Ray` amount to its original (unscaled) value by
/// multiplying by `index`, rounding half up.
pub fn scaled_to_original(env: &Env, scaled: Ray, index: Ray) -> Ray {
    scaled.mul(env, index)
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

**File:** contracts/pool/src/ops/market.rs (L60-72)
```rust
/// Accrues interest for each market in `hub_assets` and emits one state event
/// per market.
///
/// Always commits state so same-ledger simulation records the write footprint
/// needed if time advances before transaction inclusion.
pub(crate) fn accrue(env: &Env, hub_assets: Vec<HubAssetKey>) {
    renew_instance(env);

    for hub_asset in hub_assets.iter() {
        let mut cache = Cache::load(env, &hub_asset);
        interest::global_sync(env, &mut cache);
        events::emit_market_state(env, cache.commit());
    }
```

**File:** tests/test-harness/tests/controller/large_positions_and_long_horizons.rs (L315-353)
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
```

**File:** tests/test-harness/tests/controller/large_positions_and_long_horizons.rs (L354-356)
```rust
    // The market is frozen: exits and repayments accrue first and hit the same panic.
    assert_contract_error(t.try_withdraw_raw(BOB, "BIG18", 1), errors::MATH_OVERFLOW);
    assert_contract_error(t.try_repay(ALICE, "BIG18", 1.0), errors::MATH_OVERFLOW);
```

**File:** contracts/pool/src/lib.rs (L150-171)
```rust
    /// Burns supply shares and transfers the underlying to `receiver`.
    /// `is_liquidation` skips the max-utilization check and may withhold a
    /// protocol fee. Owner-only; `actual_amount` is gross of that fee.
    #[only_owner]
    fn withdraw(
        env: Env,
        receiver: Address,
        is_liquidation: bool,
        entries: Vec<PoolWithdrawEntry>,
    ) -> Vec<PoolPositionMutation> {
        ops::run_batch(&env, entries, |env, entry| {
            ops::withdraw::apply(env, &receiver, is_liquidation, entry)
        })
    }

    /// Burns scaled debt up to the repay amount, credits cash with the net
    /// repay and refunds overpayment to `payer`. Owner-only.
    #[only_owner]
    fn repay(env: Env, payer: Address, actions: Vec<PoolAction>) -> Vec<PoolPositionMutation> {
        ops::run_batch(&env, actions, |env, action| {
            ops::repay::apply(env, &payer, action)
        })
```
