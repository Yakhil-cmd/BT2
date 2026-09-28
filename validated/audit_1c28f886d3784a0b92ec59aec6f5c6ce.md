### Title
Interest accrual `scaled_to_original` overflow permanently freezes an overgrown high-utilization market - (File: common/src/rates/simulate.rs)

### Summary
The MuPDF crash class maps to a persisted-state arithmetic DoS: once a market’s scaled debt value times its borrow index exceeds `i128`, the next mandatory accrual panics before the borrow-index cap can protect the market. Every money-moving path accrues first, so the panic becomes a market freeze rather than a single failed transaction.

### Finding Description
`accrue_step` starts every accrual by reconstructing `borrowed_original` and `supplied_original` with `scaled_to_original` before updating indexes. [1](#0-0)  `scaled_to_original` is `Ray::mul`, which calls `fp_core::mul_div_half_up`. [2](#0-1) [3](#0-2)  The widened `I256` path is exact but still returns `None` when the final quotient does not fit `i128`, and `mul_div_half_up` converts that into `GenericError::MathOverflow`. [4](#0-3) 

The pool runs `interest::global_sync` inside `ops::market::accrue` and through the normal operation flow before mutations; `accrue_chunk` calls `accrue_step` and then commits the resulting indexes. [5](#0-4) [6](#0-5)  The borrow-index cap in `update_borrow_index` does not bound the `borrowed * index` value consumed earlier in `accrue_step`, and `calculate_supplier_rewards` also multiplies `borrowed` by both old and new borrow indexes. [7](#0-6) [8](#0-7) 

The reachable controller surface is the listed permissionless set: an account supplies and borrows through controller `supply`/`borrow`, keeps utilization high, and any later `update_indexes`, `supply`, `borrow`, `withdraw`, `repay`, `liquidate`, or `clean_bad_debt` touching that `HubAssetKey` reaches pool accrual. Controller `repay` and `liquidate` are explicitly permissionless entrypoints, and pool `update_indexes` performs the accrual/commit for each `HubAssetKey`. [9](#0-8) [10](#0-9) 

### Impact Explanation
This is permanent freezing of funds for the affected market. After the debt value crosses the `i128` Ray-value ceiling, `withdraw`, `repay`, `liquidate`, `clean_bad_debt`, `borrow`, `supply`, and `update_indexes` all hit the same `MathOverflow` before their guards or state transitions execute, because accrual is the first step. Suppliers cannot exit, borrowers cannot repay, liquidators cannot reduce risk, and bad-debt cleanup cannot run; the market remains bricked while state persists.

### Likelihood Explanation
The trigger is not a malformed argument by itself; it requires a listed market to reach an extreme Ray-scaled debt value under sustained high utilization. The repository’s own harness demonstrates the reachable cliff with an 18-decimal market at 98% utilization: once scaled debt reaches roughly `1e36` raw and the borrow index grows beyond about `170x`, `scaled_to_original` panics before `MAX_BORROW_INDEX_RAY` is reached. [11](#0-10)  Feasibility depends on real asset supply, market caps, utilization limits, and rate model chosen at listing, so this is a conditional Medium rather than an always-available crash.

### Recommendation
Do not let accrual consume an unbounded `borrowed * index` product. In `accrue_step`, clamp or explicitly handle the case where `scaled_to_original(env, borrowed, borrow_index)` or `scaled_to_original(env, supplied, supply_index)` exceeds the `i128` Ray domain before calling `utilization`/`calculate_supplier_rewards`. Prefer saturating valuation for utilization/rate selection, cap `new_borrow_index` before computing `borrowed.mul(new_borrow_index)`, and add a regression test proving `update_indexes`, `repay`, `withdraw`, and `liquidate` still execute at the ceiling rather than reverting forever.

### Proof of Concept
The in-repo reproducer is `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` in `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:321-360`. It builds `BIG18`/`COL`, supplies `1e9 * 1e18` `BIG18`, borrows 98% of it, advances ledger time, and observes `try_update_indexes_for(&["BIG18"])` fail with `MATH_OVERFLOW`; subsequent `try_withdraw_raw` and `try_repay` fail the same way while `borrow_index` remains below `MAX_BORROW_INDEX_RAY`. [12](#0-11) 

Minimal call sequence, assuming a market whose parameters permit the required size/utilization:

```rust
// caller-owned liquidity only
controller.supply(supplier, account_id, vec![(HubAssetKey { hub_id, asset }, huge_supply)], None);
controller.borrow(borrower, account_id, vec![(HubAssetKey { hub_id, asset }, huge_debt)], None);
// after ledger time advances, any of these permanently reverts:
controller.update_indexes(caller, vec![HubAssetKey { hub_id, asset }]);
controller.repay(payer, account_id, vec![(HubAssetKey { hub_id, asset }, 1)]);
controller.withdraw(supplier, account_id, vec![(HubAssetKey { hub_id, asset }, 1)], None);
controller.liquidate(liquidator, account_id, vec![(HubAssetKey { hub_id, asset }, 1)], SeizeMode::Transfer);
```

### Citations

**File:** common/src/rates/simulate.rs (L51-66)
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
```

**File:** common/src/rates/scaling.rs (L12-16)
```rust
/// Converts a scaled `Ray` amount to its original (unscaled) value by
/// multiplying by `index`, rounding half up.
pub fn scaled_to_original(env: &Env, scaled: Ray, index: Ray) -> Ray {
    scaled.mul(env, index)
}
```

**File:** common/src/math/fp.rs (L49-52)
```rust
    /// Multiplies two ray values, rounding the result half up.
    pub fn mul(self, env: &Env, other: Ray) -> Ray {
        Ray(fp_core::mul_div_half_up(env, self.0, other.0, RAY))
    }
```

**File:** common/src/math/fp_core.rs (L120-143)
```rust
/// Computes `x * y / d` rounded half up. Returns `None` if `x < 0`, `y < 0`, `d <= 0`, or the
/// result does not fit in `i128`.
pub fn try_mul_div_half_up(env: &Env, x: i128, y: i128, d: i128) -> Option<i128> {
    if x < 0 || y < 0 || d <= 0 {
        return None;
    }
    let half = d / 2;

    // Fast path: the biased product fits `i128`, so the whole computation is
    // native. `x * y + half` is non-negative here, so `/` is the floor the
    // widened path would produce.
    if let Some(biased) = x
        .checked_mul(y)
        .and_then(|product| product.checked_add(half))
    {
        return Some(biased / d);
    }

    let (x256, y256, d256) = to_i256_operands(env, x, y, d);
    x256.mul(&y256)
        .add(&I256::from_i128(env, half))
        .div(&d256)
        .to_i128()
}
```

**File:** contracts/pool/src/interest.rs (L20-53)
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
}
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

**File:** contracts/controller/src/lib.rs (L130-164)
```rust
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
