### Title
Unbounded market-value accrual permanently freezes an oversized active market - ([File: common/src/rates/simulate.rs])

### Summary
An unprivileged borrower can drive a sufficiently large market into a state where the next index accrual cannot represent `borrowed_scaled * borrow_index` in an `i128`; because every market operation accrues first, the market then permanently rejects repayment, withdrawal, liquidation, and further index updates with `MathOverflow`. [1](#0-0) [2](#0-1) 

### Finding Description
`Controller::supply`, `Controller::borrow`, and `Controller::update_indexes` are reachable by an unprivileged authorized caller, with account ownership restricting borrow rather than requiring protocol privilege. [3](#0-2) [4](#0-3) 

The controller forwards `update_indexes` to the pool, and the pool accrues each requested market through `global_sync`, which repeatedly calls `accrue_step`. [5](#0-4) [6](#0-5) 

`accrue_step` first converts the stored scaled debt and supply to RAY-denominated values through `scaled_to_original`, and `calculate_supplier_rewards` later multiplies the same scaled debt by both the old and new borrow indexes. [7](#0-6) [8](#0-7) 

Those conversions call `Ray::mul`, which computes an exact `I256` intermediate but still requires the final RAY value to fit `i128`; otherwise it panics with `GenericError::MathOverflow`. [9](#0-8) [10](#0-9) 

The borrow index cap does not prevent this failure because it limits only the index value, not the product `borrowed_scaled * index`; a very large scaled balance crosses the representable-value ceiling before the index reaches `MAX_BORROW_INDEX_RAY`. [11](#0-10) [12](#0-11) 

Once the crossing timestamp is reached, the accrual transaction reverts before `last_timestamp` or a lower index can be committed, so every later attempt repeats the same overflowing multiplication. [13](#0-12) [14](#0-13) 

### Impact Explanation
This permanently freezes supplier funds in the affected market and prevents borrowers or liquidators from reducing the debt through the normal `repay`, `withdraw`, or `liquidate` paths, since those operations all load and accrue the market before applying their state changes. [15](#0-14) [16](#0-15) [14](#0-13) 

The protocol also loses the ability to resume accrual through `update_indexes`, and even parameter maintenance that accrues on the old curve cannot proceed without a contract upgrade. [17](#0-16) [18](#0-17) 

### Likelihood Explanation
Likelihood is medium: the attack requires a market whose caps and liquidity permit near-domain-scale balances, enough attacker collateral to establish very high utilization, and subsequent interest accrual, but all submitted entrypoints are unprivileged and validated market caps can legally approach the asset-domain maximum. [19](#0-18) [20](#0-19) 

The checked arithmetic prevents memory corruption or incorrect accounting, but it fails closed into an unrecoverable market-wide freeze rather than bounding or safely resolving the oversized accrual. [21](#0-20) [22](#0-21) 

### Recommendation
Bound admitted scaled supply and debt by the maximum future index, not merely by current asset-unit caps, or widen accrual-time market valuation to `I256` and make index progression saturate safely before any required result exceeds the `i128` domain. [23](#0-22) [7](#0-6) 

Add pre-accrual checks such as `borrowed_scaled <= i128::MAX / MAX_BORROW_INDEX_RAY` and an equivalent supply bound, enforce them at mint and revenue-share admission, and provide an emergency path that can lower debt/index state without first performing the overflowing valuation. [24](#0-23) [25](#0-24) 

### Proof of Concept
1. For an 18-decimal market, call `Controller::supply(caller=attacker, account_id=0, spoke_id=S, assets=[(H_BIG, 1_000_000_000 * 10^18)])`. [26](#0-25) [27](#0-26) 
2. On the same owned account, supply enough listed collateral in another market and call `Controller::borrow(caller=attacker, account_id=A, borrows=[(H_BIG, principal * 98 / 100)], to=Some(attacker))`; the pool mints scaled debt after passing reserves, liquidation-buffer, utilization, and post-borrow solvency checks. [28](#0-27) [24](#0-23) 
3. Let positive interest accrue until `borrowed_scaled * borrow_index / RAY` exceeds `i128::MAX`, then call `Controller::update_indexes(caller=attacker, assets=[H_BIG])`; the controller forwards the call to the pool and accrual panics in `scaled_to_original` or the corresponding debt-reward multiplication. [5](#0-4) [7](#0-6) 
4. Subsequent `update_indexes`, `withdraw`, and `repay` calls hit the same accrual panic before any corrective state can be committed; the repository’s regression test demonstrates this exact sequence and observes `MathOverflow` before `MAX_BORROW_INDEX_RAY` is reached. [2](#0-1)

### Citations

**File:** common/src/rates/simulate.rs (L51-69)
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
```

**File:** tests/test-harness/tests/controller/large_positions_and_long_horizons.rs (L316-356)
```rust
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

**File:** contracts/controller/src/lib.rs (L90-114)
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
```

**File:** contracts/controller/src/lib.rs (L367-371)
```rust
    /// Accrues pool borrow and supply indexes for `assets`. Permissionless;
    /// requires caller authorization.
    #[when_not_paused]
    fn update_indexes(env: Env, caller: Address, assets: Vec<HubAssetKey>) {
        markets::update_indexes(&env, caller, assets);
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

**File:** common/src/rates/index.rs (L13-18)
```rust
pub fn update_borrow_index(env: &Env, old_index: Ray, interest_factor: Ray) -> Ray {
    let new_index = old_index.mul(env, interest_factor);
    if new_index.raw() > MAX_BORROW_INDEX_RAY {
        return Ray::from(MAX_BORROW_INDEX_RAY);
    }
    new_index
```

**File:** common/src/rates/index.rs (L73-83)
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

**File:** common/src/math/fp_core.rs (L122-143)
```rust
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

**File:** contracts/pool/src/ops/repay.rs (L22-31)
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

**File:** contracts/pool/src/lib.rs (L110-116)
```rust
    /// Replaces the interest-rate model (curve, utilization cap, reserve
    /// factor) and flash-loan settings for a market. Accrues interest first so
    /// the old model applies through the current ledger, then writes the new
    /// model into market params. Restricted to the owner.
    #[only_owner]
    fn update_params(env: Env, hub_asset: HubAssetKey, model: InterestRateModel) {
        ops::market::replace_rate_model(&env, hub_asset, model);
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

**File:** contracts/controller/src/spoke_usage.rs (L142-156)
```rust
/// Adds scaled usage and enforces the asset-unit cap converted to RAY
/// with `index` and `decimals`.
fn enforce_spoke_cap(
    env: &Env,
    side: UsageSide,
    usage: &SpokeUsageRaw,
    delta_scaled: Ray,
    cap: i128,
    index: Ray,
    decimals: u32,
) -> Ray {
    let cap_scaled = calculate_scaled_cap(env, cap, decimals, index);
    let next_scaled = Ray::from(side.scaled(usage)).checked_add(env, delta_scaled);
    assert_with_error!(env, next_scaled <= cap_scaled, side.cap_error());
    next_scaled
```

**File:** docs/reference/formulas.md (L423-437)
```markdown
| Bound | Consequence |
|---|---|
| Asset decimals 0..=18 | Exact token-to-RAY upscaling. Below 3: collateral only, no flash loans, no liquidation fee, its account's only supply position, at least 2 whole units while in debt |
| Both indexes initially RAY; ceiling 10^36 | 10^9 times initial index; protocol constants |
| Supply-index floor 10^24 | At most 1,000 times the shares minted at index one for the same deposit |
| Borrow APR maximum 2 RAY | 200% annual rate; not a bound on balance growth alone |
| Token-to-RAY input maximum `i128::MAX / 10^(27-d)` | About 170.14 billion whole tokens, before other limits |
| Deposit conversion at the supply-index floor | About 170.14 million whole tokens before scaled-share overflow |

The token-to-RAY maximum is also the admitted cap maximum. Accrued position
values and market totals must independently fit the RAY domain; valid caps and
bounded indexes do not guarantee that future accrual fits. Value overflow can
occur before the index ceiling and block repayment/withdrawal because those
operations accrue first. At the borrow-index ceiling, further accrual produces
no borrower interest. No dedicated ceiling alarm is emitted.
```

**File:** contracts/pool/src/ops/borrow.rs (L63-79)
```rust
pub(crate) fn mint_debt(env: &Env, cache: &mut Cache, position: &mut Ray, amount: i128) {
    require_positive_amount(env, amount);
    cache.require_reserves(amount);
    guards::require_liquidation_buffer(env, cache, amount);

    let minted = cache.calculate_scaled_borrow(amount);

    assert_with_error!(
        env,
        minted.raw() > 0,
        GenericError::BorrowRoundsToZeroShares
    );

    *position = position.checked_add(env, minted);
    cache.mint_debt(minted);
    guards::require_utilization_below_max(env, cache);
}
```

**File:** contracts/controller/src/positions/debt.rs (L33-65)
```rust
pub(crate) fn process_borrow(
    env: &Env,
    caller: &Address,
    account_id: u64,
    borrows: &Vec<HubPayment>,
    to: Option<Address>,
) {
    validation::require_authorized_caller(env, caller);

    let mut account = storage::get_account(env, account_id);
    require_owner_or_delegate(env, account_id, caller, &account.owner);

    let recipient = to.unwrap_or_else(|| caller.clone());
    let mut cache = Context::new(env);
    require_external_recipient(env, &mut cache, &recipient);
    let aggregated = payments::aggregate_positive_payments(env, borrows);

    validate_position_entry_gates(
        env,
        &account,
        &aggregated,
        &mut cache,
        AccountPositionType::Borrow,
    );
    settle_borrow(env, &mut account, &recipient, &aggregated, &mut cache);

    let restamped = enforce_post_pool_solvency(env, &mut cache, &mut account);
    let sides = if restamped {
        PositionSides::Both
    } else {
        PositionSides::Debt
    };
    finalize_position_flow(env, account_id, &account, &mut cache, sides, false);
```
