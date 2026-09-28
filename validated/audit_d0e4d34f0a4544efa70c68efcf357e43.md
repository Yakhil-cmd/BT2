### Title
Interest-accrual overflow can permanently freeze a high-scale market - ([File: common/src/rates/simulate.rs])

### Summary

A market whose scaled supply or debt multiplied by its index exceeds `i128::MAX` traps during accrual before the configured index ceiling can protect it. [1](#0-0)  The panic is repeatable because every subsequent market operation loads and synchronizes the same market before applying the requested action. [2](#0-1) 

### Finding Description

`update_indexes`, `supply`, `borrow`, `withdraw`, `repay`, liquidation, flash operations, revenue claims, and recapitalization all depend on a synchronized `Cache`. [2](#0-1)  Synchronization calls `global_sync`, which processes each elapsed interval through `accrue_chunk`. [3](#0-2)  Each chunk calls `accrue_step`, which first unscaled `borrowed` and `supplied` through `scaled_to_original`. [4](#0-3)  `scaled_to_original` performs `scaled.mul(index)`, so it panics when the resulting RAY-denominated value exceeds the `i128` domain. [5](#0-4) 

The borrow index is capped only after multiplying the old index by the interest factor. [6](#0-5)  More importantly, that cap does not constrain the product `scaled_amount * index`; a large book can therefore reach the value ceiling while both indexes remain below `MAX_BORROW_INDEX_RAY` and `MAX_SUPPLY_INDEX_RAY`. [7](#0-6) 

An unprivileged borrower can create the required state by supplying collateral through `Controller::supply` and borrowing the vulnerable market through `Controller::borrow(caller, account_id, [(hub_asset, amount)], None)`. Once the condition exists, any address can trigger the repeatable failure through `Controller::update_indexes(caller, vec![hub_asset])`, which routes to the pool accrual loop. [8](#0-7) 

### Impact Explanation

After the first overflow, no later operation can advance the market past accrual. [9](#0-8)  Withdrawals and repayments fail even though they would ordinarily reduce risk, because `load_leg` synchronizes before resolving the requested amount. [10](#0-9)  Liquidation, bad-debt cleanup, and recapitalization for the same market likewise cannot complete through their normal pool paths. [10](#0-9) 

The result is permanent freezing of supplier and borrower positions in that market unless contract code is upgraded or storage is repaired externally. If the affected book contains debt, blocking repayment and liquidation can also convert an adverse price move into protocol insolvency. [11](#0-10) 

### Likelihood Explanation

The attack requires no privileged role, leaked key, oracle failure, malicious token behavior, or failed external service. The borrower does need an extremely large market: the repository’s regression scenario uses one billion units of an 18-decimal asset at 98% utilization. [12](#0-11)  Market caps and practical token supply can therefore prevent the condition for many deployments, but they are configuration constraints rather than an intrinsic code bound.

The regression demonstrates that the configured index ceiling is not reached before the value overflow, and that subsequent withdrawal and repayment attempts fail with `MathOverflow`. [13](#0-12) 

### Recommendation

Bound the scaled book itself so `supplied * MAX_SUPPLY_INDEX_RAY` and `borrowed * MAX_BORROW_INDEX_RAY` remain representable, and enforce those bounds on supply, borrow, revenue minting, and market configuration changes. Also make accrual use widened or saturating intermediate products when evaluating index growth and reward allocation, so an already-large book is clamped instead of trapping before the index cap. Add an explicit recovery-safe accrual test covering a market at the scaled-value boundary, including repay, withdraw, liquidation, and `update_indexes`. [14](#0-13) 

### Proof of Concept

The repository already contains a deterministic reproduction in `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap`. [15](#0-14)  It creates an 18-decimal market, supplies `1_000_000_000 * 10^18` base units, supplies separate collateral, and borrows 98% of the market. [12](#0-11)  Repeated calls to `try_update_indexes` eventually return `MathOverflow`; afterward, both `try_withdraw_raw` and `try_repay` fail with the same error, while the stored borrow index remains below `MAX_BORROW_INDEX_RAY`. [16](#0-15)

### Citations

**File:** common/src/rates/simulate.rs (L51-87)
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
    let supplier_shortfall = supply_index_reward_shortfall(
        env,
        supplied,
        supply_index,
        new_supply_index,
        supplier_rewards,
    );

    let protocol_reward = protocol_fee.checked_add(env, supplier_shortfall);
    // Shares are valued at the new supply index, which the caller stores for
    // this step.
    let revenue_shares = if protocol_reward == Ray::ZERO {
        Ray::ZERO
    } else {
        protocol_fee_shares(env, protocol_reward, new_supply_index, supplied)
    };
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

**File:** common/src/rates/scaling.rs (L12-16)
```rust
/// Converts a scaled `Ray` amount to its original (unscaled) value by
/// multiplying by `index`, rounding half up.
pub fn scaled_to_original(env: &Env, scaled: Ray, index: Ray) -> Ray {
    scaled.mul(env, index)
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
