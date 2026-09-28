### Title

Oversized debt book permanently freezes a market through unchecked RAY valuation overflow - (File: `common/src/rates/index.rs`)

### Summary

A sufficiently large scaled debt book causes every subsequent interest accrual to panic before the configured borrow-index ceiling can be reached. The trigger is reachable through permissionless `supply`, `borrow`, and `update_indexes`; once reached, market operations that first synchronize interest—withdrawal, repayment, and liquidation—also revert, permanently freezing user funds. [1](#0-0) [2](#0-1) [3](#0-2) 

### Finding Description

`accrue_step` converts scaled debt to its current value and later multiplies that same scaled debt by both the old and new borrow indexes to calculate accrued interest. [4](#0-3)  Both conversions eventually execute `scaled.mul(env, index)` and produce an `i128`-representable RAY value or panic. [5](#0-4) [6](#0-5) 

Although `update_borrow_index` nominally caps the index at `MAX_BORROW_INDEX_RAY`, the valuation multiplication happens at the full scaled-book size. Consequently, `borrowed_scaled * borrow_index` can exceed `i128::MAX` long before the index reaches its configured 1-billion-times ceiling. [7](#0-6) [8](#0-7) 

The repository’s directed test demonstrates this with a one-billion-token, 18-decimal market: `1e36` RAY-scaled supply and a 98% debt book overflow once the borrow index grows past roughly 170×, below `MAX_BORROW_INDEX_RAY`. [9](#0-8) 

### Impact Explanation

This is permanent freezing of all funds in the affected market. `global_sync` runs the overflowing accrual before market mutations, and the failing multiplication aborts the entire transaction before state is updated. [10](#0-9) [11](#0-10) 

The test confirms that after the accrual failure, both withdrawal and repayment revert with `MATH_OVERFLOW`; liquidation follows the same synchronized accounting path and cannot rescue the market. Because the arithmetic error occurs before the index can be persisted or capped and no smaller-time-step path avoids the oversized product, the condition is not recoverable through ordinary protocol calls. [12](#0-11) [13](#0-12) 

### Likelihood Explanation

An unprivileged attacker can create the required state by supplying a very large high-decimal asset, supplying collateral in another market, borrowing near the utilization limit, and letting sustained high borrow interest grow the index. The necessary controller calls are public and require only caller/position authorization. [1](#0-0) [14](#0-13) 

The exploit requires extreme token liquidity and sustained high utilization, so it is not economically trivial. However, neither the index ceiling nor the accrual chunking prevents the overflow: the test reaches the RAY-value ceiling before `MAX_BORROW_INDEX_RAY`, after which users cannot exit or repay. [3](#0-2) 

### Recommendation

Enforce a scaled-book invariant before the overflow boundary:

- Limit `supplied_scaled` and `borrowed_scaled` so `scaled * MAX_SUPPLY_INDEX_RAY` and `scaled * MAX_BORROW_INDEX_RAY`, respectively, fit in `i128`.
- Apply that invariant when minting supply shares, debt shares, and protocol-revenue shares—not merely at token-unit caps.
- Alternatively, calculate index valuation and accrued-interest deltas with widened arithmetic and explicitly cap/clamp to a defined representable domain, while ensuring the resulting stored totals remain safe.
- Add a regression that starts below the ceiling, advances one accrual past the overflow boundary, and verifies `withdraw`, `repay`, `liquidate`, and `update_indexes` remain executable.

A saturating conversion alone should not be used unless its insolvency or loss semantics are explicit: silently saturating debt or supply value would misstate obligations rather than merely prevent the panic.

### Proof of Concept

1. Through `Controller::supply`, deposit a very large 18-decimal asset amount, e.g. one billion whole tokens (`1e27` base units), creating `1e36` RAY-scaled supply. [15](#0-14) 
2. Supply sufficient collateral in another listed asset and call `borrow` for 98% of the large market, leaving utilization near the steep segment of the configured curve. [16](#0-15) 
3. Maintain high utilization while ledger time advances. Each permissionless `update_indexes(caller, [BIG18])` accrues through `accrue_step`, eventually pushing `borrowed_scaled * new_borrow_index` past `i128::MAX`. [17](#0-16) [4](#0-3) 
4. `update_indexes` reverts with `MATH_OVERFLOW` while `borrow_index < MAX_BORROW_INDEX_RAY`, proving that the cap did not prevent the overflow. [18](#0-17) 
5. Subsequent `withdraw` and `repay` calls revert with the same `MATH_OVERFLOW`; the market is frozen with supplier cash and borrower debt locked. [19](#0-18)

### Citations

**File:** contracts/controller/src/lib.rs (L94-114)
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
```

**File:** contracts/controller/src/lib.rs (L120-164)
```rust
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
    }

    /// Repays debt and seizes collateral at a health-factor-based bonus.
    /// Permissionless, including self-liquidation; requires liquidator authorization.
    /// Residual bad debt is socialized only at or below the collateral dust cap.
    ///
    /// `Transfer` pays pool cash and returns `0`. `Credit(id)` moves net supply
    /// shares to a different, authorized Normal-mode account on the same spoke;
    /// `Credit(0)` creates one. Credit mode needs no free collateral liquidity
    /// and returns the receiving account id.
    fn liquidate(
        env: Env,
        liquidator: Address,
        account_id: u64,
        debt_payments: Vec<(HubAssetKey, i128)>,
        seize_mode: SeizeMode,
    ) -> u64 {
        positions::liquidation::process_liquidation(
            &env,
            &liquidator,
            account_id,
            &debt_payments,
            seize_mode,
        )
    }

    /// Socializes insolvent debt into the supply index and removes the account
    /// when remaining collateral is at or below the dust cap. Permissionless;
    /// requires caller authorization.
    fn clean_bad_debt(env: Env, caller: Address, account_id: u64) {
        positions::liquidation::process_clean_bad_debt(&env, &caller, account_id);
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

**File:** common/src/rates/simulate.rs (L60-69)
```rust
    let borrowed_original = scaled_to_original(env, borrowed, borrow_index);
    let supplied_original = scaled_to_original(env, supplied, supply_index);
    let util = utilization(env, borrowed_original, supplied_original);
    let borrow_rate = calculate_borrow_rate(env, util, params);
    let interest_factor = compound_interest(env, borrow_rate, delta_ms);

    let new_borrow_index = update_borrow_index(env, borrow_index, interest_factor);

    let (supplier_rewards, protocol_fee) =
        calculate_supplier_rewards(env, params, borrowed, new_borrow_index, borrow_index);
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

**File:** common/src/constants/pool.rs (L18-23)
```rust
/// Ceiling the borrow index is clamped to after growth, in raw ray units.
pub const MAX_BORROW_INDEX_RAY: i128 = 1_000_000_000_000_000_000_000_000_000_000_000_000;

/// Ceiling the supply index is clamped to after growth, in raw ray units.
/// Equal to [`MAX_BORROW_INDEX_RAY`].
pub const MAX_SUPPLY_INDEX_RAY: i128 = MAX_BORROW_INDEX_RAY;
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

**File:** contracts/pool/src/interest.rs (L39-53)
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
