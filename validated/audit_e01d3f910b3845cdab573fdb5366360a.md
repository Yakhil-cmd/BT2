### Title
Accrual-time RAY value overflow permanently freezes a lending market - (File: common/src/rates/simulate.rs)

### Summary

A large market can grow its stored indexes until converting scaled supply or debt back to RAY value overflows `i128`, causing every subsequent market operation to revert during mandatory interest accrual. [1](#0-0) [2](#0-1) 

### Finding Description

`accrue_step` converts both `borrowed` and `supplied` scaled shares to their original values before calculating utilization and updating the indexes. [3](#0-2)   

The conversion is `scaled_to_original`, which performs checked `Ray::mul` arithmetic and raises `MathOverflow` when `scaled * index / RAY` exceeds `i128::MAX`. [2](#0-1) [4](#0-3)   

Although `update_borrow_index` caps the index at `1e36` raw RAY, the cap protects only the index value and not the already-large scaled balances multiplied by that index. [5](#0-4) [6](#0-5)   

Every pool mutation loads the market through `synced_market`, which always invokes `interest::global_sync` before executing the requested operation. [7](#0-6)   

`global_sync` processes each elapsed accrual chunk through `accrue_step`, so once the pre-accrual debt or supply valuation overflows, the transaction reverts before any repayment, withdrawal, liquidation, or index update can commit. [8](#0-7) [9](#0-8)   

The public controller exposes the affected paths through `supply`, `borrow`, `withdraw`, `repay`, `liquidate`, and the other market operations that internally call the pool. [10](#0-9) [11](#0-10) 

### Impact Explanation

Once the market crosses the representable RAY-value boundary, borrower repayment cannot reduce debt and supplier withdrawal cannot remove collateral because both operations accrue first. [7](#0-6) [12](#0-11)   

The result is permanent freezing of supplier funds and a permanently unusable market rather than a temporary fail-closed rejection. [13](#0-12) 

### Likelihood Explanation

An unprivileged attacker can create or use an account, supply the target asset and sufficient collateral through `Controller::supply`, and borrow the target asset through `Controller::borrow` without privileged authorization. [14](#0-13)   

The attack requires a high-decimal market whose configured caps admit a very large position and sustained high utilization until index growth makes the scaled debt or supply valuation exceed `i128::MAX`; the repository’s regression test reaches the cliff with a one-billion-whole-token, 18-decimal market at 98% utilization. [15](#0-14)   

The preconditions are capital- and configuration-dependent, but they do not require privileged calls during the attack, malformed token behavior, oracle manipulation, or a third-party victim action. [16](#0-15) 

### Recommendation

Enforce a scaled-share ceiling derived from the maximum index, such as requiring `supplied <= i128::MAX * RAY / MAX_SUPPLY_INDEX_RAY` and `borrowed <= i128::MAX * RAY / MAX_BORROW_INDEX_RAY`, instead of limiting only asset-unit deposits and borrows. [6](#0-5) [17](#0-16)   

The check must also cover revenue shares minted during accrual, because `protocol_fee_shares` can grow total `supplied` after the initial cap check. [18](#0-17) [19](#0-18) 

### Proof of Concept

The following sequence is reachable by one unprivileged caller controlling the supplied liquidity, collateral, and borrower account:

```rust
// A is the same unprivileged caller.
let target = HubAssetKey { hub_id, asset: token18 };
let collateral = HubAssetKey { hub_id, asset: collateral_token };

// account_id = 0 creates the caller's account.
let account_id = controller.supply(
    attacker,
    0,
    spoke_id,
    vec![(collateral, sufficient_collateral)],
);

// Add the target market's liquidity to the same account.
controller.supply(
    attacker,
    account_id,
    spoke_id,
    vec![(target, 1_000_000_000 * 10_i128.pow(18))],
);

// Establish sustained high utilization.
controller.borrow(
    attacker,
    account_id,
    vec![(target, 980_000_000 * 10_i128.pow(18))],
    Some(attacker),
);

// After enough ledger time has elapsed, even explicit accrual fails.
controller.update_indexes(attacker, vec![target]);
```

The repository’s harness performs the equivalent large-market setup, advances the ledger until `update_indexes` returns `MathOverflow`, and confirms that `borrow_index` remains below `MAX_BORROW_INDEX_RAY`. [20](#0-19)   

It then verifies that both a minimal withdrawal and a repayment revert with the same `MathOverflow`, demonstrating that the market cannot recover through its normal exit paths. [21](#0-20)

### Citations

**File:** common/src/rates/simulate.rs (L60-66)
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

**File:** common/src/rates/scaling.rs (L20-32)
```rust
/// The division saturates at `i128::MAX` instead of panicking, so the cap check
/// fails open rather than trapping an entry path. The asset-to-RAY
/// rescale still panics on overflow; listings validate caps with
/// [`crate::validation::require_cap_within_asset_domain`]. Position accounting
/// uses [`calculate_scaled_supply`] and [`calculate_scaled_borrow`], which panic
/// on overflow.
pub fn calculate_scaled_cap(env: &Env, cap: i128, decimals: u32, index: Ray) -> Ray {
    Ray::from(fp_core::mul_div_floor_saturating(
        env,
        Ray::from_asset(env, cap, decimals).raw(),
        RAY,
        index.raw(),
    ))
```

**File:** common/src/math/fp.rs (L49-52)
```rust
    /// Multiplies two ray values, rounding the result half up.
    pub fn mul(self, env: &Env, other: Ray) -> Ray {
        Ray(fp_core::mul_div_half_up(env, self.0, other.0, RAY))
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

**File:** common/src/rates/index.rs (L91-99)
```rust
/// Converts a Ray-denominated `fee` into scaled supply-index shares
/// (`fee / supply_index`), floor-rounded and saturating on overflow. Caps the
/// result so that adding it to `supplied` cannot overflow `i128::MAX`.
pub fn protocol_fee_shares(env: &Env, fee: Ray, supply_index: Ray, supplied: Ray) -> Ray {
    let raw = fp_core::mul_div_floor_saturating(env, fee.raw(), RAY, supply_index.raw());

    let headroom = i128::MAX.saturating_sub(supplied.raw());
    Ray::from(raw.min(headroom))
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

**File:** contracts/pool/src/ops/mod.rs (L29-34)
```rust
/// Loads a market cache and accrues interest through the current ledger time.
pub(crate) fn synced_market(env: &Env, hub_asset: &HubAssetKey) -> Cache {
    let mut cache = Cache::load(env, hub_asset);
    interest::global_sync(env, &mut cache);
    cache
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

**File:** contracts/pool/src/interest.rs (L50-52)
```rust
    cache.set_borrow_index(step.borrow_index);
    cache.set_supply_index(step.supply_index);
    cache.accrue_revenue(step.revenue_shares);
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

**File:** contracts/controller/src/lib.rs (L90-127)
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
```

**File:** contracts/controller/src/lib.rs (L130-158)
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

**File:** tests/test-harness/tests/controller/large_positions_and_long_horizons.rs (L354-360)
```rust
    // The market is frozen: exits and repayments accrue first and hit the same panic.
    assert_contract_error(t.try_withdraw_raw(BOB, "BIG18", 1), errors::MATH_OVERFLOW);
    assert_contract_error(t.try_repay(ALICE, "BIG18", 1.0), errors::MATH_OVERFLOW);
    std::println!(
        "ray-value cliff reached after {years} years at 98 percent utilization on the XLM curve; last index x{:.1}",
        last.borrow_index as f64 / RAY as f64
    );
```
