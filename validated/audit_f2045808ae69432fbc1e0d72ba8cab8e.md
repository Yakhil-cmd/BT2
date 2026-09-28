### Title

Unchecked debt-value overflow before the borrow-index cap permanently freezes a large market - (File: common/src/rates/index.rs)

### Summary

Interest accrual can panic with `MathOverflow` while computing the new total debt before `MAX_BORROW_INDEX_RAY` is reached. After that state is reached, every controller operation touching the market calls the pool's accrual path and fails, leaving suppliers unable to withdraw, borrowers unable to repay, and liquidators unable to liquidate.

### Finding Description

`update_borrow_index` caps the new index only after `old_index.mul(interest_factor)` succeeds. `calculate_supplier_rewards` then computes `borrowed.mul(old_borrow_index)` and `borrowed.mul(new_borrow_index)`. [1](#0-0) [2](#0-1) 

`Ray::mul` uses checked `i128` fixed-point arithmetic and panics as `GenericError::MathOverflow` when the result is not representable. [3](#0-2)  Consequently, `borrowed * borrow_index` can overflow while `borrow_index` remains below `MAX_BORROW_INDEX_RAY`.

The overflow propagates through `accrue_chunk` and `global_sync`, which run before pool mutations. [4](#0-3) [5](#0-4)  The public controller paths `update_indexes`, `withdraw`, `repay`, and `liquidate` therefore all fail once the market reaches the overflow boundary. [6](#0-5) [7](#0-6) [8](#0-7) 

### Impact Explanation

This is a permanent market-wide denial of service for funds held in the affected `(hub_id, asset)` book. Supplier principal and accrued yield cannot be withdrawn, borrower repayments cannot be processed, and liquidations cannot reduce risk; the existing test demonstrates that both `withdraw` and `repay` fail with `MATH_OVERFLOW` after `update_indexes` fails. [9](#0-8) 

The normal parameter-remediation path does not provide recovery because `upgrade_liquidity_pool_params` calls `pool_update_indexes_call` before replacing the rate model, so it encounters the same accrual panic before updating the dangerous parameters. [10](#0-9) 

### Likelihood Explanation

The trigger requires a very large supplied balance, sustained high utilization, and enough elapsed time for the fixed-point debt value to approach `i128::MAX`. The regression test creates the condition permissionlessly with an 18-decimal market, approximately one billion whole tokens supplied, 98% borrowed, and repeated `update_indexes` calls until accrual fails. [11](#0-10) 

Although the liquidity and maturity requirements make the issue less likely than an immediate arithmetic flaw, no privileged action is needed once such a market exists. Any unprivileged caller can advance the market to the failing accrual through `Controller::update_indexes`.

### Recommendation

Bound the index by the maximum representable debt value rather than relying only on `MAX_BORROW_INDEX_RAY`. In `common/src/rates/index.rs`, calculate a market-specific ceiling such as `min(MAX_BORROW_INDEX_RAY, i128::MAX / borrowed_scaled)` before multiplying debt by the index, and make accrual saturate at that safe ceiling instead of panicking. Apply the same pre-division check to `old_index * interest_factor` so index multiplication cannot overflow before the cap is applied. Add a regression test proving that after the cliff boundary `repay`, `withdraw`, `liquidate`, and parameter updates continue to execute or deterministically stop accrual without freezing the market.

### Proof of Concept

1. Configure an 18-decimal market using the steep interest-rate curve and remove utilization and supply-cap restrictions.
2. Through `Controller::supply`, deposit approximately `1_000_000_000 * 10^18` units of the market asset.
3. Supply sufficient collateral in a separate market and call `Controller::borrow` for 98% of the first market's liquidity.
4. Advance ledger time until `debt_scaled * next_borrow_index` exceeds `i128::MAX`.
5. Call `Controller::update_indexes(caller, vec![HubAssetKey { hub_id, asset }])`; it fails with `MathOverflow`.
6. Subsequent `withdraw`, `repay`, or `liquidate` calls on that market fail for the same reason because each performs accrual first.

The repository already contains this scenario as `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap`; it asserts the index cap was not reached and confirms that withdrawal and repayment revert with `MATH_OVERFLOW`. [9](#0-8)

### Citations

**File:** common/src/rates/index.rs (L13-18)
```rust
pub fn update_borrow_index(env: &Env, old_index: Ray, interest_factor: Ray) -> Ray {
    let new_index = old_index.mul(env, interest_factor);
    if new_index.raw() > MAX_BORROW_INDEX_RAY {
        return Ray::from(MAX_BORROW_INDEX_RAY);
    }
    new_index
```

**File:** common/src/rates/index.rs (L80-83)
```rust
    let old_total_debt = borrowed.mul(env, old_borrow_index);
    let new_total_debt = borrowed.mul(env, new_borrow_index);

    let accrued_interest = new_total_debt.checked_sub(env, old_total_debt);
```

**File:** common/src/math/fp.rs (L49-52)
```rust
    /// Multiplies two ray values, rounding the result half up.
    pub fn mul(self, env: &Env, other: Ray) -> Ray {
        Ray(fp_core::mul_div_half_up(env, self.0, other.0, RAY))
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

**File:** contracts/controller/src/markets.rs (L89-100)
```rust
pub(crate) fn upgrade_liquidity_pool_params(
    env: &Env,
    hub_asset: &HubAssetKey,
    params: &InterestRateModel,
) {
    let mut cache = Context::new(env);

    let pool_addr = cache.cached_pool_address();

    pool_update_indexes_call(env, &pool_addr, &vec![env, hub_asset.clone()]);

    pool_update_params_call(env, &pool_addr, hub_asset, params);
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

**File:** contracts/controller/src/lib.rs (L120-133)
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
```

**File:** contracts/controller/src/lib.rs (L144-158)
```rust
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
```

**File:** tests/test-harness/tests/controller/large_positions_and_long_horizons.rs (L321-344)
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
```

**File:** tests/test-harness/tests/controller/large_positions_and_long_horizons.rs (L347-356)
```rust
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
