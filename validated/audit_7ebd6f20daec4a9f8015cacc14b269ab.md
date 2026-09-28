### Title
Overflowing index-scaled market totals permanently freeze repayments and withdrawals - (File: common/src/rates/simulate.rs)

### Summary
The market accrual path multiplies aggregate scaled supply and debt by their RAY indexes using `i128`-bounded fixed-point arithmetic. Once either aggregate product exceeds `i128::MAX`, every subsequent accrual panics with `MathOverflow`, permanently preventing withdrawals, repayments, liquidations, and index updates for that market.

### Finding Description
`accrue_step` computes aggregate debt and supply by calling `scaled_to_original`, which evaluates `scaled * index` and panics if the result does not fit in `i128`. [1](#0-0) [2](#0-1)  The borrow-index cap only limits the index itself and does not ensure that `borrowed * borrow_index` or `supplied * supply_index` remains representable. [3](#0-2) 

The public `Controller::update_indexes` path is permissionless and invokes the pool accrual routine. [4](#0-3) [5](#0-4)  The pool loops over all elapsed chunks and only marks the market accrued after the loop completes, so a panic leaves `last_timestamp` unchanged and causes every later call to retry the same overflowing accrual. [6](#0-5) [7](#0-6) 

This condition is reachable through ordinary markets because scaled caps intentionally saturate rather than enforce a strict representable upper bound. [8](#0-7)  Repayment and withdrawal operations perform interest accrual before reducing positions, so neither operation can reduce the oversized scaled balance after the threshold is crossed. [9](#0-8) [10](#0-9) 

### Impact Explanation
All funds in the affected market are permanently frozen. Suppliers cannot withdraw because withdrawal accrues first, borrowers cannot repay because repayment accrues first, and liquidation cannot restore solvency because it also depends on the same accrual path. [11](#0-10) [12](#0-11) 

Because failed accrual never advances `last_timestamp`, the overflow is self-reinforcing rather than a one-time revert. [13](#0-12)  The result is permanent freezing of user funds and a market that cannot operate from its persisted state.

### Likelihood Explanation
An unprivileged caller can create the necessary state through `supply` and `borrow`, then trigger accrual through `update_indexes`. [14](#0-13) [4](#0-3)  The attack requires an extremely large indexed market position and favorable market parameters or caps, so it is less practical than an ordinary direct drain, but no privileged action is needed once the market configuration permits the required scale.

The failure mode is deterministic: once `scaled * index` exceeds `i128::MAX`, the widened fixed-point result still cannot be represented as `i128`, and conversion panics with `MathOverflow`. [15](#0-14) 

### Recommendation
Prevent aggregate scaled balances from reaching a value whose unscaled representation cannot fit in the accounting domain. In particular:

- Enforce caps and position mutations against the exact scaled limit rather than a saturating `i128::MAX` cap.
- Before minting supply or debt shares, verify that both the resulting scaled balance and `scaled * index` remain below a protocol-defined safe bound.
- Track a `max_scaled_by_index` domain or equivalent invariant per market instead of relying only on token-denominated caps.
- Add regression coverage that accrual, repay, withdraw, liquidation, and `update_indexes` remain executable near the representability boundary.

### Proof of Concept
1. An attacker calls `Controller.supply(caller, 0, spoke_id, [(hub_asset, amount)])` with an amount permitted by the market configuration.
2. Using collateral in another listed market, the attacker calls `Controller.borrow(caller, account_id, [(hub_asset, borrow_amount)], None)` until the market has a very large scaled debt balance.
3. After ledger time advances, the attacker calls `Controller.update_indexes(caller, [hub_asset])`.
4. `pool::interest::global_sync` invokes `accrue_step`, which evaluates `scaled_to_original(borrowed, borrow_index)` or `scaled_to_original(supplied, supply_index)`. [16](#0-15) [17](#0-16) 
5. If the product exceeds `i128::MAX`, `Ray::mul` reaches `mul_div_half_up` and panics with `GenericError::MathOverflow`. [18](#0-17) [19](#0-18) 
6. The transaction reverts before `mark_accrued`, leaving `last_timestamp` unchanged. Subsequent `update_indexes`, `withdraw`, `repay`, and `liquidate` transactions retry accrual from the same timestamp and fail on the same overflowing product. [6](#0-5) [20](#0-19)

### Citations

**File:** common/src/rates/simulate.rs (L51-71)
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

    let (supplier_rewards, protocol_fee) =
        calculate_supplier_rewards(env, params, borrowed, new_borrow_index, borrow_index);

    let new_supply_index = update_supply_index(env, supplied, supply_index, supplier_rewards);
```

**File:** common/src/rates/scaling.rs (L12-16)
```rust
/// Converts a scaled `Ray` amount to its original (unscaled) value by
/// multiplying by `index`, rounding half up.
pub fn scaled_to_original(env: &Env, scaled: Ray, index: Ray) -> Ray {
    scaled.mul(env, index)
}
```

**File:** common/src/rates/scaling.rs (L18-33)
```rust
/// Converts an asset-unit `cap` to a scaled `Ray` value, rounding down.
///
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
}
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

**File:** contracts/controller/src/lib.rs (L120-158)
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

**File:** contracts/pool/src/cache/mod.rs (L133-146)
```rust
    /// Milliseconds between last accrual and the stamped current time.
    pub(crate) fn elapsed_ms(&self) -> u64 {
        self.current_timestamp.saturating_sub(self.last_timestamp)
    }

    /// `true` when interest should be compounded before further mutations.
    pub(crate) fn needs_accrual(&self) -> bool {
        self.elapsed_ms() > 0
    }

    /// Marks the market as fully accrued through `current_timestamp`.
    pub(crate) fn mark_accrued(&mut self) {
        self.last_timestamp = self.current_timestamp;
    }
```

**File:** contracts/pool/src/ops/repay.rs (L22-60)
```rust
/// Accrues interest, burns the position's debt shares, credits the net repay to cash,
/// commits the market state, and transfers any overpayment back to the payer.
/// The returned mutation's `actual_amount` is the net repay, excluding overpayment.
pub(crate) fn apply(
    env: &Env,
    payer: &Address,
    action: &PoolAction,
) -> (PoolPositionMutation, MarketStateSnapshot) {
    let outcome = accounting(env, action);

    outcome.cache.transfer_out(payer, outcome.overpayment);
    (outcome.mutation, outcome.snapshot)
}

/// Accrues interest, resolves the repay amount into burned debt shares and
/// overpayment, burns the shares, and credits the net repay to cash without
/// transferring the overpayment refund. Panics if a positive net repay would
/// burn zero scaled shares.
pub(crate) fn accounting(env: &Env, action: &PoolAction) -> RepayOutcome {
    let (mut cache, position) = ops::load_leg(env, action);
    let amount = action.amount;

    let (burned, overpayment) = cache.resolve_repay(amount, position);
    let net_repay = amount
        .checked_sub(overpayment)
        .unwrap_or_else(|| panic_with_error!(env, GenericError::MathOverflow));
    assert_with_error!(
        env,
        net_repay == 0 || burned.raw() > 0,
        GenericError::RepayRoundsToZeroShares
    );

    let position = position.checked_sub(env, burned);
    cache.burn_debt(burned);

    cache.credit_cash(net_repay);

    let snapshot = cache.commit();
    let mutation = cache.position_mutation(position, net_repay);
```

**File:** contracts/pool/src/ops/withdraw.rs (L25-36)
```rust
/// Accrues interest, burns supply shares, debits cash, and transfers the net
/// proceeds to `receiver`.
///
/// Mutation `actual_amount` is the **gross** withdrawal; `net_transfer` is what
/// leaves the pool after any liquidation fee.
pub(crate) fn apply(
    env: &Env,
    receiver: &Address,
    is_liquidation: bool,
    entry: &PoolWithdrawEntry,
) -> (PoolPositionMutation, MarketStateSnapshot) {
    let outcome = accounting(env, is_liquidation, entry);
```

**File:** contracts/pool/src/ops/withdraw.rs (L53-81)
```rust
/// Runs withdraw accounting without transferring tokens.
///
/// Resolves full or partial close, burns shares, optionally withholds the
/// liquidation fee, and gates the final state before debiting cash.
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
        env,
        &mut cache,
        gross_amount,
        is_liquidation,
        entry.protocol_fee,
    );

    // A footprint-only close must not add a utilization gate to same-market
    // net settlement: it burns no shares and moves no cash.
    let empty_close = position.raw() == 0 && entry.action.amount == i128::MAX;
    gate_and_debit(env, &mut cache, net_transfer, is_liquidation || empty_close);

    let snapshot = cache.commit();
```

**File:** common/src/math/fp_core.rs (L104-118)
```rust
/// Computes `x * y / d` rounded half up. Requires `x >= 0`, `y >= 0`, and `d > 0`; a
/// `debug_assert` checks this in debug builds. Panics with `GenericError::DivisionByZero` if
/// `d == 0`, and with `GenericError::MathOverflow` if any other precondition is violated or if
/// the result does not fit in `i128`.
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

**File:** common/src/math/fp_core.rs (L298-303)
```rust
/// Converts an `I256` to `i128`, panicking with `GenericError::MathOverflow` if it does not
/// fit.
fn to_i128(env: &Env, val: &I256) -> i128 {
    val.to_i128()
        .unwrap_or_else(|| panic_with_error!(env, GenericError::MathOverflow))
}
```

**File:** common/src/math/fp.rs (L184-187)
```rust
    /// Multiplies two wad values, rounding the result half up.
    pub fn mul(self, env: &Env, other: Wad) -> Wad {
        Wad(fp_core::mul_div_half_up(env, self.0, other.0, WAD))
    }
```
