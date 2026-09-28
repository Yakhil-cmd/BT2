### Title
Unchecked RAY-scaled index multiplication permanently freezes an oversized high-utilization market - ([File: common/src/rates/index.rs](common/src/rates/index.rs))

### Summary
Interest accrual multiplies stored scaled balances by RAY indexes before the configured index ceiling can protect the market. Once `scaled * index` exceeds `i128::MAX`, accrual reverts, and because market actions synchronize interest first, affected suppliers and borrowers can no longer withdraw, repay, or liquidate. [1](#0-0) [2](#0-1) 

### Finding Description
`global_sync` chunks elapsed time and calls `accrue_chunk`, which updates both indexes through `accrue_step` before committing market state. [3](#0-2)  The accrual arithmetic derives total supplied and borrowed values by multiplying scaled `Ray` balances by their indexes, while `scaled_to_original` performs the multiplication without a market-size bound. [4](#0-3) [2](#0-1)  Although `update_borrow_index` caps the resulting index at `MAX_BORROW_INDEX_RAY`, that cap is applied only after multiplication and does not prevent the preceding value-domain overflow. [5](#0-4) 

The existing regression test demonstrates the exact cliff: a one-billion-token market using 18 decimals and 98% utilization eventually causes `update_indexes` to return `MathOverflow` while `borrow_index` remains below `MAX_BORROW_INDEX_RAY`. [6](#0-5) 

### Impact Explanation
This permanently freezes the affected market rather than merely rejecting one oversized transaction. [7](#0-6)  The test shows subsequent `withdraw` and `repay` calls fail with the same `MathOverflow`, meaning supplier principal and borrower collateral remain locked because each path requires accrual before mutation. [7](#0-6)  `update_params` also synchronizes the market before changing the rate model, so switching to a safer interest model does not provide a recovery path once the overflow has been reached. [8](#0-7) 

### Likelihood Explanation
An unprivileged user can reach the precondition through normal `supply`, `borrow`, and `update_indexes` flows: supply a very large amount of a high-decimals asset, borrow at sustained high utilization under sufficient collateral, and allow interest to compound. [9](#0-8) [10](#0-9)  The scenario requires an unusually large permitted market and prolonged high utilization, so it is less likely than an ordinary input-validation failure, but it is reachable with amounts allowed by the tested configuration and has permanent impact once crossed. [11](#0-10) 

### Recommendation
Enforce a market-level invariant that every stored scaled balance remains safely below `i128::MAX / index` before accrual, not merely an index ceiling after multiplication. [5](#0-4)  Accrual should clamp the index or bound `scaled * index` before calculating utilization, rewards, or debt growth, and supply/borrow caps should be reduced to preserve that invariant for each asset’s decimal domain. [2](#0-1) [12](#0-11) 

### Proof of Concept
1. Configure an 18-decimal market with a sufficiently high supply/borrow cap and a steep interest-rate curve.
2. Call `supply` with `principal = 1_000_000_000 * 10^18` base units.
3. Supply collateral and call `borrow` for approximately `principal * 98 / 100`, producing 98% utilization.
4. Advance ledger time and repeatedly call `update_indexes` for that market.
5. The call eventually fails with `MathOverflow` while `borrow_index < MAX_BORROW_INDEX_RAY`.
6. Subsequent `withdraw` and `repay` calls fail with `MathOverflow`, leaving the market permanently frozen. [13](#0-12)

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

**File:** common/src/rates/scaling.rs (L12-16)
```rust
/// Converts a scaled `Ray` amount to its original (unscaled) value by
/// multiplying by `index`, rounding half up.
pub fn scaled_to_original(env: &Env, scaled: Ray, index: Ray) -> Ray {
    scaled.mul(env, index)
}
```

**File:** contracts/pool/src/cache/scale.rs (L19-26)
```rust
    pub(crate) fn calculate_utilization(&self) -> Ray {
        if self.supplied == Ray::ZERO {
            return Ray::ZERO;
        }
        let total_borrowed = scaled_to_original(&self.env, self.borrowed, self.borrow_index);
        let total_supplied = scaled_to_original(&self.env, self.supplied, self.supply_index);

        utilization(&self.env, total_borrowed, total_supplied)
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

**File:** contracts/pool/src/lib.rs (L128-148)
```rust
    /// Accrues, mints scaled supply shares and credits cash per entry. The
    /// controller transfers the tokens in before this call. Owner-only.
    #[only_owner]
    fn supply(env: Env, entries: Vec<PoolSupplyEntry>) -> Vec<PoolPositionMutation> {
        ops::run_batch(&env, entries, ops::supply::apply)
    }

    /// Batch-borrows assets and transfers them to `receiver`: accrues
    /// interest, mints scaled debt, debits cash, and enforces max
    /// utilization after each mint. Restricted to the owner; returns one
    /// [`PoolPositionMutation`] per entry.
    #[only_owner]
    fn borrow(
        env: Env,
        receiver: Address,
        entries: Vec<PoolBorrowEntry>,
    ) -> Vec<PoolPositionMutation> {
        ops::run_batch(&env, entries, |env, entry| {
            ops::borrow::apply(env, &receiver, entry)
        })
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
