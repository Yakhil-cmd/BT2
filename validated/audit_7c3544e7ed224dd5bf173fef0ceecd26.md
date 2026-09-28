### Title
Unchecked RAY aggregate accrual permanently freezes an overlarge market - (File: `common/src/rates/index.rs`)

### Summary
A sufficiently large market can reach a state where `scaled_shares * interest_index` no longer fits in `i128` before the borrow-index ceiling is reached. Interest accrual then panics, `last_timestamp` is never committed, and every later market operation repeats the same overflow, permanently freezing repayment, withdrawal, liquidation, and recapitalization for that market.

### Finding Description
Every pool mutation loads the market through `ops::synced_market`, which calls `interest::global_sync` before applying the requested operation. [1](#0-0) 

`global_sync` applies accrual through `accrue_step` and only commits the updated timestamp after all chunks complete. [2](#0-1) [3](#0-2) 

The accrual calculations multiply aggregate scaled borrow or supply shares by their indexes. [4](#0-3) [5](#0-4) 

Those multiplications return to `i128`; if the exact result exceeds `i128::MAX`, `try_mul_div_half_up` returns `None` and `mul_div_half_up` panics with `MathOverflow`. [6](#0-5) [7](#0-6) 

For an 18-decimal asset, `Ray::from_asset` multiplies the token amount by `10^9`, so one billion whole tokens becomes approximately `1e36` scaled RAY units. [8](#0-7) [9](#0-8) 

At that size, an index above roughly `170 * RAY` makes the aggregate value exceed `i128::MAX`, while the configured borrow-index ceiling remains much higher. [10](#0-9) 

Supply, borrow, repay, and withdraw all call `ops::load_leg`, which routes through `synced_market`. [11](#0-10) [12](#0-11) [13](#0-12) 

The controller exposes the required user actions through `supply`, `borrow`, `withdraw`, `repay`, `liquidate`, and permissionless `update_indexes`. [14](#0-13) [15](#0-14) [16](#0-15) [17](#0-16) 

### Impact Explanation
Once the aggregate multiplication overflows, no transaction can commit a new accrual timestamp. Because every mutation attempts accrual first, suppliers cannot withdraw, borrowers cannot repay, liquidators cannot liquidate debt in that market, and direct `update_indexes` calls cannot repair the state.

This is permanent freezing of user funds in the affected market absent an out-of-scope privileged upgrade or code migration. Other markets remain operational, so the impact is market-wide rather than protocol-wide.

### Likelihood Explanation
Exploitation requires a listed market whose caps, available token supply, collateral configuration, and utilization ceiling admit an extremely large position near the numeric domain boundary. A single unprivileged address can create the state by supplying the target asset, supplying sufficient collateral, and borrowing enough of the target asset to sustain high utilization, but the required capital and configuration make this a medium rather than high likelihood issue.

### Recommendation
Do not let accrual enter a state where market aggregate value cannot be represented.

- Track aggregate debt and supply values in a wider representation during accrual, or cap the index at the largest value that keeps `scaled_shares * index / RAY <= i128::MAX`.
- Check the impending aggregate overflow before mutating indexes and fail safe by clamping accrual rather than panicking.
- Enforce market caps that account for maximum index growth, not only initial token-to-RAY conversion.
- Add invariant tests proving that repayment, withdrawal, and liquidation remain callable at the maximum admitted scaled-share/index product.

### Proof of Concept
Assume `BIG18` is a listed 18-decimal asset whose caps and utilization configuration admit the relevant amounts, and `COL` is valid collateral.

1. The attacker calls:

   `supply(caller=attacker, account_id=0, spoke_id=valid_spoke, assets=[(BIG18, 1_000_000_000 * 10^18)])`

   This creates a scaled supply book of approximately `1e36` RAY units.

2. On the same or another attacker-owned account, the attacker supplies sufficient `COL`, then calls:

   `borrow(caller=attacker, account_id=attacker_account, borrows=[(BIG18, 980_000_000 * 10^18)], to=None)`

3. Ledger time advances until the next accrual would push `borrowed * borrow_index` or `supplied * supply_index` beyond `i128::MAX`.

4. Any caller submits:

   `update_indexes(caller=attacker, assets=[BIG18])`

   The call panics with `MathOverflow` inside the accrual multiplication before `last_timestamp` can be committed.

5. Subsequent calls that touch the market also fail before their intended mutation:

   - `repay(..., payments=[(BIG18, 1)])`
   - `withdraw(..., withdrawals=[(BIG18, 1)], ...)`
   - `liquidate(..., debt_payments=[(BIG18, amount)], SeizeMode::Transfer)`

   Each reaches `Cache::load` followed by `global_sync`, repeats the same overflow, and leaves the market frozen.

### Citations

**File:** contracts/pool/src/ops/mod.rs (L29-34)
```rust
/// Loads a market cache and accrues interest through the current ledger time.
pub(crate) fn synced_market(env: &Env, hub_asset: &HubAssetKey) -> Cache {
    let mut cache = Cache::load(env, hub_asset);
    interest::global_sync(env, &mut cache);
    cache
}
```

**File:** contracts/pool/src/ops/mod.rs (L42-47)
```rust
/// Validates `action.amount ≥ 0`, syncs the market, and returns (cache, scaled position).
pub(crate) fn load_leg(env: &Env, action: &PoolAction) -> (Cache, Ray) {
    require_nonneg_amount(env, action.amount);
    let cache = synced_market(env, &action.hub_asset);
    (cache, Ray::from(action.position.scaled_amount))
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

**File:** common/src/math/fp_core.rs (L138-143)
```rust
    let (x256, y256, d256) = to_i256_operands(env, x, y, d);
    x256.mul(&y256)
        .add(&I256::from_i128(env, half))
        .div(&d256)
        .to_i128()
}
```

**File:** common/src/math/fp_core.rs (L218-224)
```rust
    let factor = 10i128.checked_pow(to_decimals.abs_diff(from_decimals));

    if to_decimals > from_decimals {
        factor
            .and_then(|factor| a.checked_mul(factor))
            .unwrap_or_else(|| panic_with_error!(env, GenericError::MathOverflow))
    } else {
```

**File:** common/src/math/fp.rs (L139-146)
```rust
    /// Builds a `Ray` from a token amount at `asset_decimals`, rescaling half up to 27 decimals.
    pub fn from_asset(env: &Env, amount: i128, asset_decimals: u32) -> Ray {
        Ray(fp_core::rescale_half_up(
            env,
            amount,
            asset_decimals,
            RAY_DECIMALS,
        ))
```

**File:** contracts/pool/src/ops/repay.rs (L40-45)
```rust
pub(crate) fn accounting(env: &Env, action: &PoolAction) -> RepayOutcome {
    let (mut cache, position) = ops::load_leg(env, action);
    let amount = action.amount;

    let (burned, overpayment) = cache.resolve_repay(amount, position);
    let net_repay = amount
```

**File:** contracts/pool/src/ops/withdraw.rs (L57-65)
```rust
pub(crate) fn accounting(
    env: &Env,
    is_liquidation: bool,
    entry: &PoolWithdrawEntry,
) -> WithdrawOutcome {
    require_nonneg_amount(env, entry.protocol_fee);
    let (mut cache, position) = ops::load_leg(env, &entry.action);

    let (burned, gross_amount) = resolve_close_or_partial(&cache, entry.action.amount, position);
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

**File:** contracts/controller/src/lib.rs (L120-134)
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

**File:** contracts/controller/src/lib.rs (L367-372)
```rust
    /// Accrues pool borrow and supply indexes for `assets`. Permissionless;
    /// requires caller authorization.
    #[when_not_paused]
    fn update_indexes(env: Env, caller: Address, assets: Vec<HubAssetKey>) {
        markets::update_indexes(&env, caller, assets);
    }
```
