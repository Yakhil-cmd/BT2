### Title
RAY value overflow during interest accrual permanently freezes a heavily utilized market - ([File: common/src/rates/index.rs](common/src/rates/index.rs))

### Summary
The accrual path computes aggregate debt with non-saturating `RAY × RAY` fixed-point multiplication before the configured borrow-index cap can protect the market. Once scaled debt times the new borrow index exceeds `i128::MAX`, `calculate_supplier_rewards` reverts with `MathOverflow`; because market mutations accrue first, the affected market can no longer repay, withdraw, liquidate, or update indexes. [1](#0-0) [2](#0-1) 

### Finding Description
An unprivileged user reaches this state through ordinary `Controller::supply`, `Controller::borrow`, and later `Controller::update_indexes` calls. The controller exposes `update_indexes(caller, assets)` permissionlessly and forwards the selected `HubAssetKey` list to the pool. [3](#0-2) [4](#0-3) 

The pool’s `ops::market::accrue` loads each market and calls `interest::global_sync`, which invokes `accrue_step` before committing indexes and revenue. [5](#0-4) [6](#0-5) 

`calculate_supplier_rewards` then evaluates `borrowed.mul(new_borrow_index)` and `borrowed.mul(old_borrow_index)`. `Ray::mul` delegates to `mul_div_half_up`, whose widened `I256` intermediate is exact but whose final `to_i128` panics when the resulting aggregate value is unrepresentable. Thus the multiplication itself is overflow-safe, but the protocol has no bound ensuring the *result* fits the `i128` accounting domain. [7](#0-6) [8](#0-7) [9](#0-8) 

The existing `MAX_BORROW_INDEX_RAY` check only caps the index after multiplication; it does not account for the market’s scaled principal, so a sufficiently large market crosses the aggregate-value ceiling while the index remains below its nominal cap. [10](#0-9) 

### Impact Explanation
This is a permanent freezing-of-funds condition for the affected market. The repository’s directed regression test demonstrates that after the aggregate `RAY` value reaches the `i128` ceiling, `update_indexes`, `withdraw`, and `repay` all fail with `MathOverflow`, while the stored borrow index is still below `MAX_BORROW_INDEX_RAY`. [11](#0-10) 

Because accrual precedes withdrawals, repayments, liquidations, and index updates, suppliers cannot recover principal and borrowers cannot reduce debt through the affected market. The failure is not a temporary fail-closed oracle or liquidity condition: it is caused by persistent scaled state and remains reachable on every subsequent accrual. [12](#0-11) [13](#0-12) 

### Likelihood Explanation
Likelihood is constrained by the enormous position size and sustained high utilization required: the regression scenario uses a billion whole 18-decimal tokens, roughly 98% utilization, and repeated annual accrual before reaching the cliff. No privileged caller, oracle manipulation, upgrade, or invalid parameter is needed once such a market and borrow balance exist. [14](#0-13) 

The affected entrypoints are nevertheless part of the normal permissionless attack surface. Supply and borrow create the scaled balances, and any address can later invoke `update_indexes` to execute the overflowing accrual. [15](#0-14) [3](#0-2) 

### Recommendation
Bound scaled principal against the index domain rather than bounding the index alone. Enforce a per-market invariant such as `borrowed * MAX_BORROW_INDEX_RAY / RAY <= i128::MAX` and `supplied * MAX_SUPPLY_INDEX_RAY / RAY <= i128::MAX` at every supply, borrow, strategy-debt, and cap-update boundary.

Accrual should also use non-panicking arithmetic where possible: compute old/new aggregate debt through `try_mul_div_half_up`, reject or clamp the state transition before committing, and ensure `MAX_BORROW_INDEX_RAY` is low enough for the largest accepted scaled principal. A dedicated market-size cap derived from the `i128` value ceiling is safer than relying only on token-denominated caps.

### Proof of Concept
The repository already contains a directed PoC in `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap`. Its effective sequence is:

```rust
let principal = BILLION * 10i128.pow(18);
t.supply_raw(BOB, "BIG18", principal);
t.borrow_raw(ALICE, "BIG18", principal / 100 * 98);

loop {
    t.advance_time(YEAR_SECS);
    if let Err(e) = t.try_update_indexes_for(&["BIG18"]) {
        break e;
    }
}
```

The call eventually fails with `MATH_OVERFLOW`; the test then verifies that both `try_withdraw_raw(BOB, "BIG18", 1)` and `try_repay(ALICE, "BIG18", 1.0)` fail with the same error, and that `borrow_index < MAX_BORROW_INDEX_RAY`. [16](#0-15)

### Citations

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

**File:** contracts/pool/src/interest.rs (L16-32)
```rust
/// Accrues borrow/supply indexes from `last_timestamp` to the cache's current time.
///
/// No-op when no time has elapsed. Splits long gaps into max-sized compound
/// windows, then sets `last_timestamp` to `current_timestamp`.
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

**File:** contracts/pool/src/interest.rs (L39-52)
```rust
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

**File:** contracts/controller/src/external/pool.rs (L109-116)
```rust
/// Accrues and persists market indexes through the current ledger time.
pub(crate) fn pool_update_indexes_call(
    env: &Env,
    pool_addr: &Address,
    hub_assets: &Vec<HubAssetKey>,
) {
    LiquidityPoolClient::new(env, pool_addr).update_indexes(hub_assets)
}
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

**File:** common/src/math/fp.rs (L49-56)
```rust
    /// Multiplies two ray values, rounding the result half up.
    pub fn mul(self, env: &Env, other: Ray) -> Ray {
        Ray(fp_core::mul_div_half_up(env, self.0, other.0, RAY))
    }

    /// Divides this value by `other`, rounding the result half up.
    pub fn div(self, env: &Env, other: Ray) -> Ray {
        Ray(fp_core::mul_div_half_up(env, self.0, RAY, other.0))
```

**File:** common/src/math/fp_core.rs (L298-303)
```rust
/// Converts an `I256` to `i128`, panicking with `GenericError::MathOverflow` if it does not
/// fit.
fn to_i128(env: &Env, val: &I256) -> i128 {
    val.to_i128()
        .unwrap_or_else(|| panic_with_error!(env, GenericError::MathOverflow))
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
