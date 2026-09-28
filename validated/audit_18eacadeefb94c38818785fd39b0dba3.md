### Title
Unchecked RAY-value overflow during interest accrual permanently freezes a saturated market - (File: common/src/rates/index.rs)

### Summary
A user-reachable borrow can leave a sufficiently large market at sustained high utilization until its index-scaled debt or supply value exceeds `i128::MAX`; the next accrual reverts, and because every market operation accrues first, suppliers can no longer withdraw and borrowers cannot repay. [1](#0-0)  This is a permanent market-freeze condition absent a contract upgrade, matching Medium-severity impact through frozen user funds. [2](#0-1) 

### Finding Description
`Controller::update_indexes` is callable by any authenticated caller and forwards the selected assets to the pool's `update_indexes` entrypoint. [3](#0-2)  The pool entrypoint calls `ops::market::accrue`, while `global_sync` applies each elapsed-time chunk through `accrue_step`. [4](#0-3) [5](#0-4) 

The rate engine multiplies scaled balances by the old and new indexes without first bounding the resulting RAY value to the `i128` domain. [6](#0-5)  Likewise, `update_supply_index` computes `supplied * old_index` before applying the configured supply-index ceiling. [7](#0-6) 

The configured index ceiling is `1e36` RAY units, but the multiplication domain is the smaller `i128` result range. [8](#0-7)  Consequently, a market whose scaled balance is around `1e36` raw RAY can overflow when the index grows beyond roughly `170x`, long before the configured `1e9x` index cap can engage. [1](#0-0) 

### Impact Explanation
Once a market crosses this arithmetic boundary, interest accrual always panics before state is committed, so repayment and withdrawal remain permanently unavailable. [9](#0-8)  This freezes supplier principal and accrued yield in the affected market and prevents borrowers or liquidators from reducing the debt position that caused the overflow. [2](#0-1) 

The exposure is amplified because public `borrow` and `repay` flow through the same pool-market accrual machinery rather than offering a no-accrual emergency exit. [10](#0-9)  Pool withdrawal and repayment are also owner-gated only to the controller, so users cannot bypass the controller to settle their positions directly. [11](#0-10) 

### Likelihood Explanation
Exploitation requires an unusually large market and enough collateral for an attacker to borrow it into sustained high utilization; the regression fixture uses one billion whole 18-decimal tokens at 98% utilization. [12](#0-11)  The condition also requires sufficient elapsed accrual on a steep configured rate curve, so it is not an instant one-transaction attack. [13](#0-12) 

Nevertheless, all setup actions are ordinary authenticated controller calls, and no privileged market access is required at exploitation time. [14](#0-13)  The likelihood is therefore low to moderate, while the resulting impact is permanent loss of market availability and frozen user funds. [2](#0-1) 

### Recommendation
Before multiplying scaled balances by indexes, calculate the largest representable scaled value for the current index or the largest representable index for the current balance, and clamp accrual before the value exceeds `i128::MAX`. [6](#0-5)  Utilization and reward calculations should use saturating quotients or rearranged formulas that do not require materializing an overflowing `scaled * index` product. [7](#0-6) 

The borrow-index clamp should be effective before downstream value calculations can panic, rather than merely limiting `old_index * interest_factor` after multiplication. [15](#0-14)  A bounded-accrual recovery path should also allow debt repayment and supplier exit when the next calculated index would reach the arithmetic ceiling. [16](#0-15) 

### Proof of Concept
1. Configure or select a listed 18-decimal debt market `D` using a steep interest curve and a separate collateral market `C` with sufficient LTV and caps. [17](#0-16) 
2. A supplier deposits approximately `1_000_000_000 * 10^18` base units of `D`; the attacker separately calls `Controller::supply(attacker, 0, spoke_id, [(C, collateral)])`, then `Controller::borrow(attacker, account_id, [(D, debt)], Some(attacker))` for about 98% of the market liquidity. [18](#0-17) 
3. Leave the position unpaid while `global_sync` compounds the market in permitted chunks. [16](#0-15) 
4. Call `Controller::update_indexes(caller, [D])`; once the index-scaled balance exceeds the `i128` domain, `accrue_step` panics before the configured index cap is reached. [19](#0-18) 
5. Subsequent `withdraw` and `repay` calls against `D` revert with `MathOverflow` because those operations accrue first, demonstrating the permanent freeze. [2](#0-1)

### Citations

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

**File:** tests/test-harness/tests/controller/large_positions_and_long_horizons.rs (L315-319)
```rust
/// The cliff. A billion whole tokens is `1e36` raw ray; the value ceiling is
/// `i128::MAX`, 170 times that. At the XLM curve's steep segment the index
/// grows past 170x in a few years, and the next accrual panics inside
/// `scaled_to_original`. Every verb accrues first, so the market freezes:
/// no repay, no withdraw, no liquidation. The index cap never engages.
```

**File:** tests/test-harness/tests/controller/large_positions_and_long_horizons.rs (L321-333)
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
```

**File:** tests/test-harness/tests/controller/large_positions_and_long_horizons.rs (L335-356)
```rust
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

**File:** contracts/pool/src/lib.rs (L174-180)
```rust
    /// Accrues interest for each market in `hub_assets` through the current
    /// ledger time. Commits state even with no elapsed time to reserve the write
    /// footprint, and emits its market state event. Restricted to the owner.
    #[only_owner]
    fn update_indexes(env: Env, hub_assets: Vec<HubAssetKey>) {
        ops::market::accrue(&env, hub_assets);
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

**File:** common/src/rates/index.rs (L13-18)
```rust
pub fn update_borrow_index(env: &Env, old_index: Ray, interest_factor: Ray) -> Ray {
    let new_index = old_index.mul(env, interest_factor);
    if new_index.raw() > MAX_BORROW_INDEX_RAY {
        return Ray::from(MAX_BORROW_INDEX_RAY);
    }
    new_index
```

**File:** common/src/rates/index.rs (L29-41)
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
```

**File:** common/src/rates/index.rs (L73-83)
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
```

**File:** common/src/constants/pool.rs (L18-23)
```rust
/// Ceiling the borrow index is clamped to after growth, in raw ray units.
pub const MAX_BORROW_INDEX_RAY: i128 = 1_000_000_000_000_000_000_000_000_000_000_000_000;

/// Ceiling the supply index is clamped to after growth, in raw ray units.
/// Equal to [`MAX_BORROW_INDEX_RAY`].
pub const MAX_SUPPLY_INDEX_RAY: i128 = MAX_BORROW_INDEX_RAY;
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
