### Title
Index growth can push near-limit supply or debt shares past `i128`, permanently blocking withdrawal, repayment, and liquidation - (File: `common/src/rates/scaling.rs`)

### Summary
Share issuance accepts amounts whose RAY representation fits in `i128`, but later exits multiply those shares by a growing index. Because shares can start arbitrarily close to `i128::MAX`, even a one-raw-unit index increase can make the unscaled value unrepresentable, causing `MathOverflow` on every withdrawal or repayment resolution.

### Finding Description
`Controller::withdraw` maps a zero request to `i128::MAX` and forwards the position’s stored scaled amount to the pool; nonzero partial requests use the same path. [1](#0-0) [2](#0-1) 

`resolve_withdrawal` unconditionally computes both the position’s half-up and floor asset balance before deciding whether the request is partial or full. [3](#0-2) 

Both conversions execute `scaled * supply_index / RAY` through `mul_floor`/`mul`. Although the intermediate product is widened to `I256`, the final quotient must still fit in `i128` and otherwise panics with `MathOverflow`. [4](#0-3) [5](#0-4) [6](#0-5) 

Supply minting only requires `Ray::from_asset(amount, decimals)` to fit in `i128`; the configured cap validator likewise bounds only the current asset-to-RAY conversion, not that value multiplied by any future index. [7](#0-6) [8](#0-7) 

For an 18-decimal asset, `max_cap_for_decimals(18)` is `170_141_183_460_469_231_731_687_303_715` base units, producing scaled shares `S = 170_141_183_460_469_231_731_687_303_715_000_000_000` at `supply_index = RAY`. Once the index reaches `RAY + 1`, the full balance becomes approximately `S + 170_141_183_460`, which exceeds `i128::MAX = 170_141_183_460_469_231_731_687_303_715_884_105_727`. [9](#0-8) [10](#0-9) 

Normal accrual can produce that one-raw-unit increase: `accrue_step` calculates supplier rewards from borrow-index growth and calls `update_supply_index`, which computes `floor((total_supplied_value + rewards) * RAY / supplied)`. For the above `S`, rewards of about `170_141_183_460` RAY units are sufficient for `supply_index` to become `RAY + 1`. [11](#0-10) [12](#0-11) 

Debt has the same asymmetric domain problem: `calculate_scaled_borrow` accepts shares based on the old index, while `resolve_repay` unconditionally unscales the whole position through `scaled * borrow_index / RAY` before handling a partial repayment. [13](#0-12) [14](#0-13) 

### Impact Explanation
Once the index/share product crosses `i128::MAX`, every withdrawal size fails because the full position is unscalded before the requested amount is considered. The owner cannot recover the supplied tokens through `withdraw`, and transferring the position NFT does not change the arithmetic. [15](#0-14) [16](#0-15) 

For debt near the domain limit, ordinary `repay` fails in `resolve_repay`; liquidation and bad-debt accounting also depend on unscaling debt and therefore can be blocked by the same unrepresentable result. This can freeze borrower collateral and prevent the protocol from closing an increasingly risky position. [17](#0-16) [18](#0-17) 

This is permanent absent a later downward supply-index adjustment from bad-debt socialization, which is not a legitimate recovery mechanism and itself destroys supplier value. [19](#0-18) 

### Likelihood Explanation
The condition requires a very large position, but the protocol explicitly permits positions up to `max_cap_for_decimals`, and the cap check does not reserve headroom for index growth. At the 18-decimal ceiling, a one-raw-unit supply-index increase is enough to cross the boundary. [20](#0-19) [21](#0-20) 

The required index increase can be produced by ordinary borrowing and interest accrual; it does not require governance action or a malicious oracle. A borrower can use a small nonzero debt to generate supplier rewards, then call any market operation after ledger time advances, because `global_sync` runs before pool mutations. [11](#0-10) [22](#0-21) 

Lower positions can also eventually cross the boundary because `MAX_SUPPLY_INDEX_RAY` and `MAX_BORROW_INDEX_RAY` are `1e36` raw units, far above the initial `RAY`; the domain check must therefore account for index growth rather than only the entry index. [21](#0-20) [10](#0-9) 

### Recommendation
Constrain stored shares so `scaled * MAX_INDEX / RAY` remains representable, or redesign exit resolution so partial withdrawals and repayments compare share amounts directly without unscaling the entire position. At minimum, `require_cap_within_asset_domain` should include index headroom, and accrual should fail or clamp before committing an index that makes existing total supply or debt unrepresentable. [8](#0-7) [3](#0-2) 

For full withdrawals and repayments, use saturating or wide-integer balance resolution and settle in representable chunks, rather than converting the complete claim through a single `i128` result. Apply the same fix to debt resolution and every liquidation path that calls `unscale_borrow_ceil` or `unscale_supply_floor`. [23](#0-22) [14](#0-13) 

### Proof of Concept
Assume an 18-decimal borrowable asset has supply and borrow caps set to `max_cap_for_decimals(18)`.

1. Alice calls `Controller::supply(alice, 0, spoke_id, [(A, 170_141_183_460_469_231_731_687_303_715)])`; the market starts with `supply_index = RAY`, so she receives `S = 170_141_183_460_469_231_731_687_303_715_000_000_000` scaled supply shares. [24](#0-23) [25](#0-24) 

2. Any account borrows a nonzero amount of `A`, so the next elapsed-time accrual produces nonzero supplier rewards and advances `supply_index` to at least `RAY + 1`. [11](#0-10) 

3. Alice calls `Controller::withdraw(alice, account_id, [(A, 0)], None)` or requests a one-unit withdrawal. In both cases `resolve_withdrawal` first evaluates `S * (RAY + 1) / RAY`, producing a value greater than `i128::MAX`, so `to_i128` panics with `MathOverflow`. [26](#0-25) [27](#0-26) 

4. Repeating the call with any positive amount follows the same unconditional full-position valuation and fails identically, leaving Alice’s shares and the underlying cash trapped. [15](#0-14)

### Citations

**File:** contracts/controller/src/lib.rs (L90-102)
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
```

**File:** contracts/controller/src/lib.rs (L117-128)
```rust
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
```

**File:** contracts/controller/src/positions/supply.rs (L180-199)
```rust
    let mut entries: Vec<PoolWithdrawEntry> = Vec::new(env);
    for (hub_asset, amount) in aggregated.iter() {
        enforce_spoke_asset_flags(
            env,
            cache,
            account.spoke_id,
            &hub_asset,
            FreezePolicy::AllowOnExit,
        );
        let position = get_supply_position_or_panic(env, account, &hub_asset);
        let requested = if amount == 0 {
            WITHDRAW_ALL_SENTINEL
        } else {
            amount
        };
        entries.push_back(PoolWithdrawEntry {
            action: make_pool_action(&position, requested, hub_asset.clone()),
            protocol_fee: 0,
        });
    }
```

**File:** common/src/rates/scaling.rs (L35-50)
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
```

**File:** common/src/rates/scaling.rs (L52-66)
```rust
/// Converts an asset-unit `amount` to a scaled borrow `Ray` using ceiling
/// rounding relative to `borrow_index`.
pub fn calculate_scaled_borrow(env: &Env, amount: i128, decimals: u32, borrow_index: Ray) -> Ray {
    Ray::from_asset(env, amount, decimals).div_ceil(env, borrow_index)
}

/// Converts an asset-unit `amount` to a scaled borrow `Ray` using floor
/// rounding relative to `borrow_index`.
pub fn calculate_scaled_borrow_floor(
    env: &Env,
    amount: i128,
    decimals: u32,
    borrow_index: Ray,
) -> Ray {
    Ray::from_asset(env, amount, decimals).div_floor(env, borrow_index)
```

**File:** common/src/rates/scaling.rs (L69-95)
```rust
/// Converts a scaled supply `Ray` back to an asset-unit amount, using
/// half-up rounding at `decimals` precision.
pub fn unscale_supply(env: &Env, scaled: Ray, supply_index: Ray, decimals: u32) -> i128 {
    scaled_to_original(env, scaled, supply_index).to_asset(env, decimals)
}

/// Converts a scaled supply `Ray` back to an asset-unit amount, using floor
/// rounding at `decimals` precision.
pub fn unscale_supply_floor(env: &Env, scaled: Ray, supply_index: Ray, decimals: u32) -> i128 {
    scaled
        .mul_floor(env, supply_index)
        .to_asset_floor(env, decimals)
}

/// Converts a scaled borrow `Ray` back to an asset-unit amount, using
/// half-up rounding at `decimals` precision.
pub fn unscale_borrow(env: &Env, scaled: Ray, borrow_index: Ray, decimals: u32) -> i128 {
    scaled_to_original(env, scaled, borrow_index).to_asset(env, decimals)
}

/// Converts a scaled borrow `Ray` back to an asset-unit amount, using
/// ceiling rounding at `decimals` precision.
pub fn unscale_borrow_ceil(env: &Env, scaled: Ray, borrow_index: Ray, decimals: u32) -> i128 {
    scaled
        .mul_ceil(env, borrow_index)
        .to_asset_ceil(env, decimals)
}
```

**File:** common/src/rates/scaling.rs (L105-120)
```rust
pub fn resolve_withdrawal(
    env: &Env,
    amount: i128,
    pos_scaled: Ray,
    supply_index: Ray,
    decimals: u32,
) -> (Ray, i128) {
    let current_supply_actual = unscale_supply(env, pos_scaled, supply_index, decimals);
    let current_supply_floor = unscale_supply_floor(env, pos_scaled, supply_index, decimals);
    if amount >= current_supply_actual {
        return (pos_scaled, current_supply_floor);
    }
    (
        calculate_scaled_supply_ceil(env, amount, decimals, supply_index),
        amount,
    )
```

**File:** common/src/rates/scaling.rs (L171-190)
```rust
pub fn resolve_repay(
    env: &Env,
    amount: i128,
    pos_scaled: Ray,
    borrow_index: Ray,
    decimals: u32,
) -> (Ray, i128) {
    let current_debt_ceil = unscale_borrow_ceil(env, pos_scaled, borrow_index, decimals);
    if amount >= current_debt_ceil {
        (
            pos_scaled,
            amount
                .checked_sub(current_debt_ceil)
                .unwrap_or_else(|| panic_with_error!(env, GenericError::MathOverflow)),
        )
    } else {
        (
            calculate_scaled_borrow_floor(env, amount, decimals, borrow_index),
            0,
        )
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

**File:** common/src/math/fp_core.rs (L148-158)
```rust
pub fn mul_div_floor(env: &Env, x: i128, y: i128, d: i128) -> i128 {
    require_nonzero_divisor(env, d);
    if let Some(quotient) = x
        .checked_mul(y)
        .and_then(|product| div_floor_i128(product, d))
    {
        return quotient;
    }
    let (x256, y256, d256) = to_i256_operands(env, x, y, d);
    let nonneg = quotient_is_nonnegative(x, y, d);
    to_i128(env, &div_floor_i256(env, &x256.mul(&y256), &d256, nonneg))
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

**File:** common/src/validation.rs (L41-70)
```rust
/// Returns the largest cap, in asset base units, whose ray-scaled form still
/// fits in `i128`.
///
/// Returns 0 when `asset_decimals > RAY_DECIMALS`, since the ray form is not
/// representable in that case. Enforced by
/// [`require_cap_within_asset_domain`], so stored caps can never overflow the
/// asset→ray rescale.
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

**File:** contracts/pool/src/ops/market.rs (L35-41)
```rust
        &PoolStateRaw {
            supplied: 0,
            borrowed: 0,
            revenue: 0,
            borrow_index: RAY,
            supply_index: RAY,
            last_timestamp: time::now_ms(env),
```

**File:** common/src/rates/simulate.rs (L60-72)
```rust
    let borrowed_original = scaled_to_original(env, borrowed, borrow_index);
    let supplied_original = scaled_to_original(env, supplied, supply_index);
    let util = utilization(env, borrowed_original, supplied_original);
    let borrow_rate = calculate_borrow_rate(env, util, params);
    let interest_factor = compound_interest(env, borrow_rate, delta_ms);

    let new_borrow_index = update_borrow_index(env, borrow_index, interest_factor);

    let (supplier_rewards, protocol_fee) =
        calculate_supplier_rewards(env, params, borrowed, new_borrow_index, borrow_index);

    let new_supply_index = update_supply_index(env, supplied, supply_index, supplier_rewards);
    let supplier_shortfall = supply_index_reward_shortfall(
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

**File:** contracts/pool/src/ops/withdraw.rs (L63-80)
```rust
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

```

**File:** contracts/pool/src/ops/seize.rs (L23-31)
```rust
    match entry.side {
        AccountPositionType::Borrow => {
            let bad_debt = cache.unscale_borrow_ceil_ray(position);
            interest::apply_bad_debt_to_supply_index(&mut cache, bad_debt);
            cache.burn_debt(position);
        }
        AccountPositionType::Deposit => {
            cache.absorb_supply_as_revenue(position);
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

**File:** contracts/pool/src/interest.rs (L73-89)
```rust
pub(crate) fn apply_bad_debt_to_supply_index(cache: &mut Cache, bad_debt: Ray) {
    let total_supplied_value = cache.supplied().mul(cache.env(), cache.supply_index());

    if total_supplied_value == Ray::ZERO {
        return;
    }

    let capped = bad_debt.min(total_supplied_value);
    let remaining = total_supplied_value.checked_sub(cache.env(), capped);

    let reduction_factor = remaining.div_floor(cache.env(), total_supplied_value);
    let new_supply_index = cache
        .supply_index()
        .mul_floor(cache.env(), reduction_factor);

    cache.set_supply_index(new_supply_index.max(Ray::from(SUPPLY_INDEX_FLOOR_RAW)));
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

**File:** contracts/pool/src/ops/supply.rs (L23-36)
```rust
    let (mut cache, mut position) = ops::load_leg(env, &entry.action);
    let amount = entry.action.amount;

    guards::require_backed_market(env, &cache);

    let minted = cache.calculate_scaled_supply(amount);
    assert_with_error!(
        env,
        amount == 0 || minted.raw() > 0,
        GenericError::SupplyRoundsToZeroShares
    );

    position = position.checked_add(env, minted);
    cache.mint_supply(minted);
```
