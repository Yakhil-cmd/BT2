### Title
RAY-scaled debt multiplication overflows `i128` and permanently freezes a market - (File: common/src/rates/scaling.rs)

### Summary
Scaled debt and supply are converted back to RAY-denominated value by multiplying scaled shares by their indexes. [1](#0-0)  Although intermediate products are widened to `I256`, the quotient must still fit in `i128`; otherwise the conversion panics with `MathOverflow`. [2](#0-1) [3](#0-2)  A sufficiently large market can therefore reach a state where the next accrual would make `borrowed * borrow_index / RAY` unrepresentable before the global index ceiling is reached. [4](#0-3) [5](#0-4) 

### Finding Description
Permissionless `Controller::update_indexes` forwards the requested markets to the pool. [6](#0-5)  The pool loads each market and calls `interest::global_sync` before committing it. [7](#0-6)  `global_sync` invokes `accrue_step` with the market’s scaled borrowed total and live indexes. [8](#0-7) [9](#0-8) 

The accrual path needs the total debt value, including through `calculate_supplier_rewards`, which multiplies scaled debt by both the old and new borrow indexes. [10](#0-9)  Utilization performs the same `scaled * index` conversion through `scaled_to_original`. [11](#0-10)  Once either product’s normalized value exceeds `i128::MAX`, `Ray::mul` panics rather than returning a usable result. [12](#0-11) [13](#0-12) 

For example, an 18-decimal asset deposit of one billion whole tokens produces approximately `1e36` scaled RAY units; at 98% utilization, the debt-value conversion exceeds `i128::MAX` when the borrow index reaches roughly 174 times its initial value, while the configured borrow-index ceiling is `1e9` times the initial value. [14](#0-13) [5](#0-4)  Caps may legally admit this scale because validation only bounds the token-to-RAY conversion, not the later `scaled amount * index` result. [15](#0-14) 

### Impact Explanation
After the market crosses the boundary, the failed accrual transaction rolls back, leaving the same state that causes the next accrual attempt to fail again. [16](#0-15)  Repayment and withdrawal cannot bypass this failure because their pool legs call `load_leg`, which always syncs the market before operating. [17](#0-16) [18](#0-17) [19](#0-18) 

The result is permanent freezing of supplier funds and borrower collateral absent a contract upgrade or other privileged rescue. [20](#0-19)  It also prevents normal repayment, liquidation-driven settlement, and further index updates for the affected market. [21](#0-20) 

### Likelihood Explanation
The trigger uses only public, caller-authorized paths: supply, borrow, and update indexes. [22](#0-21) [6](#0-5)  It requires a valid market with whale-scale caps and enough collateral to sustain very high utilization until accrual reaches the arithmetic boundary. [15](#0-14)  The required configuration is within the protocol’s admitted numeric domain, but the capital requirement and accrual precondition make this a Medium-severity availability issue rather than an easily repeatable attack. [23](#0-22) 

### Recommendation
Track a market-specific index ceiling equal to the largest index for which `scaled * index / RAY` remains representable, and clamp accrual to that value instead of panicking. [24](#0-23)  Apply the equivalent headroom check when minting supply or debt so admitted positions cannot grow past the largest safely unscalable total. [25](#0-24)  Separately, use saturating conversion or an explicit accrued-interest cutoff inside `calculate_supplier_rewards` so the accrual transaction can commit a bounded terminal index rather than reverting permanently. [26](#0-25) 

### Proof of Concept
Assume a valid 18-decimal `BIG` market whose supply and borrow caps are near `max_cap_for_decimals(18)`, and a 7-decimal collateral market with sufficient cap. [27](#0-26) 

```rust
// One unprivileged caller creates and funds an account.
let big = HubAssetKey { hub_id, asset: big_token };
let col = HubAssetKey { hub_id, asset: col_token };
let big_amount: i128 = 1_000_000_000 * 10i128.pow(18);
let col_amount: i128 = 2_000_000_000 * 10i128.pow(7);

let account_id = controller.supply(
    attacker,
    0,
    spoke_id,
    vec![(big.clone(), big_amount), (col, col_amount)],
);

// Draw 98% of the BIG liquidity.
controller.borrow(
    attacker,
    account_id,
    vec![(big.clone(), big_amount * 98 / 100)],
    None,
);

// Advance ledger time and repeatedly sync until debt value exceeds i128::MAX.
controller.update_indexes(attacker, vec![big.clone()]); // eventually MathOverflow

// Every later synced operation fails on the same arithmetic boundary.
controller.repay(attacker, account_id, vec![(big.clone(), 1)]); // MathOverflow
controller.withdraw(attacker, account_id, vec![(big, 1)], None); // MathOverflow
```

The `i128::MAX` boundary is crossed before the global `MAX_BORROW_INDEX_RAY` can engage, so subsequent accruals keep reverting and the market remains frozen. [5](#0-4) [3](#0-2)

### Citations

**File:** common/src/rates/scaling.rs (L12-16)
```rust
/// Converts a scaled `Ray` amount to its original (unscaled) value by
/// multiplying by `index`, rounding half up.
pub fn scaled_to_original(env: &Env, scaled: Ray, index: Ray) -> Ray {
    scaled.mul(env, index)
}
```

**File:** common/src/rates/scaling.rs (L35-56)
```rust
/// Converts an asset-unit `amount` to a scaled supply `Ray` using floor
/// rounding relative to `supply_index`.
pub fn calculate_scaled_supply(env: &Env, amount: i128, decimals: u32, supply_index: Ray) -> Ray {
    Ray::from_asset(env, amount, decimals).div_floor(env, supply_index)
}

/// Converts an asset-unit `amount` to a scaled supply `Ray` using ceiling
/// rounding relative to `supply_index`.
pub fn calculate_scaled_supply_ceil(
    env: &Env,
    amount: i128,
    decimals: u32,
    supply_index: Ray,
) -> Ray {
    Ray::from_asset(env, amount, decimals).div_ceil(env, supply_index)
}

/// Converts an asset-unit `amount` to a scaled borrow `Ray` using ceiling
/// rounding relative to `borrow_index`.
pub fn calculate_scaled_borrow(env: &Env, amount: i128, decimals: u32, borrow_index: Ray) -> Ray {
    Ray::from_asset(env, amount, decimals).div_ceil(env, borrow_index)
}
```

**File:** common/src/math/fp_core.rs (L108-118)
```rust
pub fn mul_div_half_up(env: &Env, x: i128, y: i128, d: i128) -> i128 {
    // The zero check runs first so debug and release builds agree on a zero
    // divisor: both surface `DivisionByZero` rather than tripping the assert.
    require_nonzero_divisor(env, d);
    debug_assert!(
        x >= 0 && y >= 0 && d > 0,
        "mul_div_half_up: non-negative x, y and positive d"
    );
    try_mul_div_half_up(env, x, y, d)
        .unwrap_or_else(|| panic_with_error!(env, GenericError::MathOverflow))
}
```

**File:** common/src/math/fp_core.rs (L138-143)
```rust
    let (x256, y256, d256) = to_i256_operands(env, x, y, d);
    x256.mul(&y256)
        .add(&I256::from_i128(env, half))
        .div(&d256)
        .to_i128()
}
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

**File:** common/src/constants/pool.rs (L11-23)
```rust
/// Upper bound accepted for a pool's configured maximum borrow rate, in raw ray units.
pub const MAX_BORROW_RATE_RAY: i128 = 2 * RAY;

/// Share of supplied value, in BPS, that pool cash must still cover after any
/// debt mint, borrows and strategy openings alike (INV-ACCT-07).
pub const LIQUIDATION_BUFFER_BPS: i128 = 200;

/// Ceiling the borrow index is clamped to after growth, in raw ray units.
pub const MAX_BORROW_INDEX_RAY: i128 = 1_000_000_000_000_000_000_000_000_000_000_000_000;

/// Ceiling the supply index is clamped to after growth, in raw ray units.
/// Equal to [`MAX_BORROW_INDEX_RAY`].
pub const MAX_SUPPLY_INDEX_RAY: i128 = MAX_BORROW_INDEX_RAY;
```

**File:** contracts/controller/src/lib.rs (L90-115)
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

**File:** contracts/controller/src/lib.rs (L136-158)
```rust
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

**File:** contracts/controller/src/lib.rs (L367-372)
```rust
    /// Accrues pool borrow and supply indexes for `assets`. Permissionless;
    /// requires caller authorization.
    #[when_not_paused]
    fn update_indexes(env: Env, caller: Address, assets: Vec<HubAssetKey>) {
        markets::update_indexes(&env, caller, assets);
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

**File:** contracts/pool/src/cache/scale.rs (L19-27)
```rust
    pub(crate) fn calculate_utilization(&self) -> Ray {
        if self.supplied == Ray::ZERO {
            return Ray::ZERO;
        }
        let total_borrowed = scaled_to_original(&self.env, self.borrowed, self.borrow_index);
        let total_supplied = scaled_to_original(&self.env, self.supplied, self.supply_index);

        utilization(&self.env, total_borrowed, total_supplied)
    }
```

**File:** common/src/math/fp.rs (L49-52)
```rust
    /// Multiplies two ray values, rounding the result half up.
    pub fn mul(self, env: &Env, other: Ray) -> Ray {
        Ray(fp_core::mul_div_half_up(env, self.0, other.0, RAY))
    }
```

**File:** common/src/math/fp.rs (L119-121)
```rust
    /// Rescales from 27 decimals to `asset_decimals`, rounding half up.
    pub fn to_asset(self, env: &Env, asset_decimals: u32) -> i128 {
        fp_core::rescale_half_up(env, self.0, RAY_DECIMALS, asset_decimals)
```

**File:** common/src/validation.rs (L48-70)
```rust
pub fn max_cap_for_decimals(asset_decimals: u32) -> i128 {
    let Some(exp) = RAY_DECIMALS.checked_sub(asset_decimals) else {
        return 0;
    };
    let upscale = 10i128
        .checked_pow(exp)
        .expect("10^(RAY_DECIMALS - asset_decimals) fits i128 for asset_decimals <= RAY_DECIMALS");
    i128::MAX / upscale
}

/// Panics with `CollateralError::AssetDecimalsTooHigh` if `asset_decimals`
/// exceeds `RAY_DECIMALS`, or with `CollateralError::InvalidBorrowParams` if
/// `cap` exceeds the value returned by `max_cap_for_decimals`.
pub fn require_cap_within_asset_domain(env: &Env, cap: i128, asset_decimals: u32) {
    if RAY_DECIMALS.checked_sub(asset_decimals).is_none() {
        panic_with_error!(env, CollateralError::AssetDecimalsTooHigh);
    }
    assert_with_error!(
        env,
        cap <= max_cap_for_decimals(asset_decimals),
        CollateralError::InvalidBorrowParams
    );
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

**File:** contracts/pool/src/ops/repay.rs (L40-45)
```rust
pub(crate) fn accounting(env: &Env, action: &PoolAction) -> RepayOutcome {
    let (mut cache, position) = ops::load_leg(env, action);
    let amount = action.amount;

    let (burned, overpayment) = cache.resolve_repay(amount, position);
    let net_repay = amount
```

**File:** contracts/pool/src/ops/withdraw.rs (L57-68)
```rust
pub(crate) fn accounting(
    env: &Env,
    is_liquidation: bool,
    entry: &PoolWithdrawEntry,
) -> WithdrawOutcome {
    require_nonneg_amount(env, entry.protocol_fee);
    let (mut cache, position) = ops::load_leg(env, &entry.action);

    let (burned, gross_amount) = resolve_close_or_partial(&cache, entry.action.amount, position);
    // Burn first: `protocol_fee_shares` caps the fee mint at `i128::MAX - supplied`.
    let remaining = burn_position(env, &mut cache, position, burned);
    let net_transfer = withhold_liquidation_fee(
```
