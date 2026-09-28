### Title
RAY value overflow during mandatory interest accrual permanently freezes a large market - (File: `common/src/rates/simulate.rs`)

### Summary
A market whose scaled balances and indexes produce a RAY value exceeding `i128::MAX` cannot complete the mandatory pre-operation accrual. The overflow occurs while computing utilization in `accrue_step`, before the borrow-index cap can protect the operation. [1](#0-0) 

### Finding Description
`accrue_step` first converts scaled borrowed and supplied balances to RAY asset values with `scaled_to_original`. That helper directly calls `scaled.mul(index)`, which raises `MathOverflow` when the resulting RAY value exceeds `i128`. [2](#0-1) [3](#0-2) 

Every state-changing pool leg loads a synchronized market through `synced_market` or `load_leg`, both of which call `interest::global_sync` before performing the requested operation. [4](#0-3)  `global_sync` invokes `accrue_chunk`, which delegates to `accrue_step`, so the overflow traps before any operation-specific accounting can run. [5](#0-4) 

The borrow-index cap is ineffective because `accrue_step` must multiply the already-stored scaled debt by the already-stored index to determine utilization. The index can remain below `MAX_BORROW_INDEX_RAY` while `borrowed * borrow_index / RAY` exceeds `i128::MAX`. [6](#0-5) 

The regression test demonstrates the exact condition: one billion 18-decimal tokens creates a RAY-scale principal of `1e36`; after sustained high utilization, an index near 170× makes the next accrual panic with `MathOverflow`. [7](#0-6) 

### Impact Explanation
Once the stored `(borrowed, borrow_index)` or `(supplied, supply_index)` pair crosses the representable-value boundary, the market cannot recover through normal entrypoints:

- `Controller::repay` cannot burn debt because pool `repay` calls `load_leg` and syncs first. [8](#0-7) 
- `Controller::withdraw` cannot release collateral because pool `withdraw` calls `load_leg` and syncs first. [9](#0-8) 
- `Controller::liquidate` and `Controller::clean_bad_debt` cannot operate on the market because `seize_positions` syncs before burning debt or reclassifying supply. [10](#0-9) 
- Permissionless `Controller::update_indexes` also fails because it executes `global_sync` for the market. [11](#0-10) 
- Even the owner-only `upgrade_liquidity_pool_params` path cannot reduce the rate, because `replace_rate_model` deliberately accrues under the old model before replacing it. [12](#0-11) 

The test confirms that both withdrawal and repayment revert with `MathOverflow` after the cliff is reached. [13](#0-12)  Therefore suppliers' collateral and borrowers' ability to repay are permanently unavailable unless an out-of-band contract upgrade changes the arithmetic or state.

### Likelihood Explanation
The trigger requires a very large market and enough elapsed time at high utilization for the relevant index to push the RAY-denominated book value above `i128::MAX`. A single unprivileged caller can establish this state by calling `Controller::supply` for both the debt asset and collateral, `Controller::borrow` for a large position, and later `Controller::update_indexes`; all are reachable without privileged authority. [14](#0-13) [15](#0-14) 

The cost is substantial and depends on governance admitting an asset/rate/cap configuration where such balances are permitted. However, once ordinary users share the market, one account can place the market at the boundary and later permissionlessly trigger accrual, freezing every user's funds in that market. This is persistent accounting unavailability rather than a bounded, fail-closed rejection.

### Recommendation
Enforce the arithmetic domain as a market invariant rather than relying on index caps after balances already exist:

- At supply/debt mint time, require both `scaled_amount * supply_index / RAY` and `scaled_amount * borrow_index / RAY` to remain below a safety margin under `i128::MAX`, including headroom for future index growth.
- Alternatively, perform accrual totals in `I256` and fail safely or clamp utilization without panicking, while keeping exact share accounting bounded.
- Add an emergency non-accrual path for repayment, withdrawal, or socialization only if it can avoid unsafe accounting; otherwise the recovery path must not call `global_sync`.
- Extend `accrue_step` to detect the overflow before converting both totals and return a protocol-handled state or bounded utilization result rather than trapping.

The least invasive defense is a mint-time ceiling derived from the configured maximum indexes, because it prevents an impossible book-value state from being committed.

### Proof of Concept
The repository already contains a deterministic reproduction in `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs`:

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

assert_contract_error(
    t.try_withdraw_raw(BOB, "BIG18", 1),
    errors::MATH_OVERFLOW,
);
assert_contract_error(
    t.try_repay(ALICE, "BIG18", 1.0),
    errors::MATH_OVERFLOW,
);
``` [16](#0-15) 

The equivalent production path is:

1. Call `Controller::supply(caller, 0, spoke_id, [(BIG18, 1e27)])`.
2. Call `Controller::supply(caller, account_id, spoke_id, [(COL, sufficient_collateral)])`.
3. Call `Controller::borrow(caller, account_id, [(BIG18, 0.98e27)], None)`.
4. After enough high-rate accrual, call `Controller::update_indexes(caller, [BIG18])`.
5. Subsequent `withdraw`, `repay`, `liquidate`, `clean_bad_debt`, `claim_revenue`, and `recapitalize` calls involving `BIG18` revert during the mandatory accrual.

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

**File:** common/src/rates/index.rs (L13-19)
```rust
pub fn update_borrow_index(env: &Env, old_index: Ray, interest_factor: Ray) -> Ray {
    let new_index = old_index.mul(env, interest_factor);
    if new_index.raw() > MAX_BORROW_INDEX_RAY {
        return Ray::from(MAX_BORROW_INDEX_RAY);
    }
    new_index
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

**File:** contracts/pool/src/ops/repay.rs (L36-45)
```rust
/// Accrues interest, resolves the repay amount into burned debt shares and
/// overpayment, burns the shares, and credits the net repay to cash without
/// transferring the overpayment refund. Panics if a positive net repay would
/// burn zero scaled shares.
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

**File:** contracts/pool/src/ops/seize.rs (L14-27)
```rust
/// Applies one seize entry, syncing the market, socializing bad debt or
/// reclassifying supply as revenue depending on `entry.side`, and returns the
/// committed market snapshot. Does not transfer tokens; the controller adjusts
/// the position books. Panics if `entry.position.scaled_amount` is negative.
pub(crate) fn apply(env: &Env, entry: &PoolSeizeEntry) -> MarketStateSnapshot {
    require_nonneg_amount(env, entry.position.scaled_amount);
    let mut cache = ops::synced_market(env, &entry.hub_asset);
    let position = Ray::from(entry.position.scaled_amount);

    match entry.side {
        AccountPositionType::Borrow => {
            let bad_debt = cache.unscale_borrow_ceil_ray(position);
            interest::apply_bad_debt_to_supply_index(&mut cache, bad_debt);
            cache.burn_debt(position);
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

**File:** contracts/controller/src/lib.rs (L90-133)
```rust
    /// Supplies `assets` as collateral and returns the account id; `account_id = 0`
    /// creates an account in `spoke_id`. Third parties may only top up existing
    /// supply positions; owners and delegates may add assets.
    #[when_not_paused]
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

    /// Withdraws collateral to `to` or the caller and returns actual amounts in
    /// asset units. Zero withdraws an asset's full position. Requires owner or
    /// delegate authorization and post-withdrawal solvency.
    fn withdraw(
        env: Env,
        caller: Address,
        account_id: u64,
        withdrawals: Vec<(HubAssetKey, i128)>,
        to: Option<Address>,
    ) -> Vec<(HubAssetKey, i128)> {
        positions::process_withdraw(&env, &caller, account_id, &withdrawals, to)
    }

    /// Repays `account_id`'s debt using measured payments from the caller.
    /// Anyone may repay; excess payments are refunded to the caller.
    fn repay(env: Env, caller: Address, account_id: u64, payments: Vec<(HubAssetKey, i128)>) {
        positions::process_repay(&env, &caller, account_id, &payments);
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
