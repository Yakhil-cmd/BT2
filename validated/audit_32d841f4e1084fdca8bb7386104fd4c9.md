### Title
Scaled-debt valuation overflows before the index cap and permanently freezes a market - (File: common/src/rates/scaling.rs)

### Summary
A sufficiently large borrowed position can push `borrowed * borrow_index` past `i128::MAX` before `borrow_index` reaches `MAX_BORROW_INDEX_RAY`. [1](#0-0) [2](#0-1)  Because interest accrual performs that multiplication before updating or capping the index, the next accrual panics with `MathOverflow` instead of clamping the index. [3](#0-2) [4](#0-3) 

### Finding Description
Each accrual starts by un-scaling aggregate debt and supply through `scaled_to_original`, which multiplies the stored scaled amount by the stored index. [5](#0-4) [3](#0-2)  The borrow-index ceiling is applied only after utilization has already been calculated and `update_borrow_index` has run, so it cannot prevent overflow in the pre-update valuation. [6](#0-5) [4](#0-3) 

Every pool mutation loads the market through `synced_market`, and `synced_market` unconditionally calls `interest::global_sync`. [7](#0-6)  `global_sync` processes elapsed time through `accrue_chunk`, which calls the vulnerable `accrue_step`; therefore withdrawal, repayment, liquidation, borrowing, supply, and explicit index updates all hit the same panic once the stored product exceeds `i128::MAX`. [8](#0-7) [9](#0-8) 

The public controller path is `update_indexes(caller, assets)`, which authorizes any caller and forwards the selected hub assets to the pool. [10](#0-9)  Pool-side `update_indexes` delegates directly to `ops::market::accrue`, while `withdraw`, `repay`, `borrow`, and `supply` all use operation paths that call `synced_market`. [11](#0-10) [7](#0-6) 

### Impact Explanation
Once `borrowed * borrow_index` is unrepresentable, the market cannot accrue again. [1](#0-0)  Since every state-changing market operation accrues first, suppliers cannot withdraw, borrowers cannot repay, liquidators cannot liquidate, and protocol revenue cannot be claimed for that market. [7](#0-6) [12](#0-11) 

This is permanent freezing rather than a transient denial of service: the stored `borrowed` and `borrow_index` remain unchanged after the failed transaction, so every later accrual repeats the overflowing multiplication. [8](#0-7) [3](#0-2)  The repository's regression test demonstrates this exact state: `update_indexes` fails with `MATH_OVERFLOW`, the stored index remains below `MAX_BORROW_INDEX_RAY`, and subsequent withdrawal and repayment attempts fail identically. [13](#0-12) 

### Likelihood Explanation
The trigger requires a very large market and sustained high utilization, but it does not require privileged calls, leaked keys, malformed parameters, oracle manipulation, or a third-party dependency. [10](#0-9) [1](#0-0)  A funded attacker can supply the target asset and collateral, borrow the target asset at high utilization, and later invoke public `update_indexes`; other users' funds in that market are frozen when the boundary is crossed. [14](#0-13) 

The concrete demonstrated trigger is a one-billion-whole-token, 18-decimal market at approximately 98% utilization. [15](#0-14)  The test shows that the value ceiling is reached before the intended index ceiling, making the failure a real accounting-domain boundary rather than merely an unreachable theoretical overflow. [16](#0-15) [17](#0-16) 

### Recommendation
Do not require `borrowed * index` and `supplied * index` to fit in `i128` before deciding utilization or applying the index cap. [3](#0-2) [1](#0-0)  Compute utilization with a wider intermediate or a quotient-first formulation, or detect that the debt value is above the protocol ceiling and clamp to the configured index cap in a way that preserves a recoverable accrual path. [4](#0-3) [2](#0-1) 

The fix should ensure `MAX_BORROW_INDEX_RAY` engages before the aggregate-value overflow and should be regression-tested with the existing large-market scenario. [2](#0-1) [13](#0-12) 

### Proof of Concept
For an existing 18-decimal market whose caps permit the position, a funded attacker calls `controller.supply(attacker, account_id, spoke_id, [(hub_asset, 1_000_000_000 * 10^18)])`, supplies sufficient collateral in another market, and calls `controller.borrow(attacker, account_id, [(hub_asset, 980_000_000 * 10^18)], None)` to establish approximately 98% utilization. [18](#0-17)  At index `RAY`, the scaled debt is approximately `9.8e35`, so it only needs index growth beyond roughly `i128::MAX / 9.8e35`, far below the configured `1e36` index ceiling. [3](#0-2) [2](#0-1) 

After enough ledger time, the attacker calls `controller.update_indexes(attacker, [hub_asset])`; the pool executes `global_sync`, `accrue_step`, and the overflowing `scaled_to_original(borrowed, borrow_index)` before `update_borrow_index` can apply its cap. [10](#0-9) [8](#0-7) [19](#0-18)  The repository test then observes `MATH_OVERFLOW`, confirms `borrow_index < MAX_BORROW_INDEX_RAY`, and confirms that both `withdraw` and `repay` fail afterward because those paths accrue first. [13](#0-12) [7](#0-6)

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

**File:** common/src/constants/pool.rs (L18-23)
```rust
/// Ceiling the borrow index is clamped to after growth, in raw ray units.
pub const MAX_BORROW_INDEX_RAY: i128 = 1_000_000_000_000_000_000_000_000_000_000_000_000;

/// Ceiling the supply index is clamped to after growth, in raw ray units.
/// Equal to [`MAX_BORROW_INDEX_RAY`].
pub const MAX_SUPPLY_INDEX_RAY: i128 = MAX_BORROW_INDEX_RAY;
```

**File:** common/src/rates/scaling.rs (L12-16)
```rust
/// Converts a scaled `Ray` amount to its original (unscaled) value by
/// multiplying by `index`, rounding half up.
pub fn scaled_to_original(env: &Env, scaled: Ray, index: Ray) -> Ray {
    scaled.mul(env, index)
}
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

**File:** contracts/pool/src/ops/mod.rs (L29-40)
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

**File:** contracts/pool/src/lib.rs (L128-171)
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

**File:** tests/test-harness/tests/controller/large_positions_and_long_horizons.rs (L315-343)
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
