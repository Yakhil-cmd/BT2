### Title
RAY-scaled debt/supply valuation can overflow `i128` before the index cap and permanently freeze a market - (File: common/src/rates/scaling.rs)

### Summary
The accrual path values scaled debt and supply as `scaled * index` in `i128` RAY terms. For a very large market, this product can exceed `i128::MAX` while the borrow index is still far below `MAX_BORROW_INDEX_RAY`, so `scaled_to_original` / `calculate_supplier_rewards` panic with `MathOverflow` before the index cap can clamp growth. Because every pool mutation accrues first, once the product crosses the `i128` ceiling the market can no longer accrue, repay, withdraw, liquidate, or settle bad debt.

### Finding Description
`accrue_step` computes `borrowed_original` and `supplied_original` via `scaled_to_original`, which is just `scaled.mul(env, index)`; `Ray::mul` uses `mul_div_half_up`, which returns a typed `MathOverflow` panic when the exact quotient does not fit `i128`. [1](#0-0) [2](#0-1) [3](#0-2) 

The borrow index is only capped after `old_index.mul(interest_factor)`; the cap is `1e36` raw RAY, while the `i128` value ceiling can be hit near index ≈170 for a `1e36` scaled book. [4](#0-3) [5](#0-4) 

`interest::global_sync` runs `accrue_step` before committing every market mutation, and pool README documents `Cache::load → global_sync → mutate` for each market entrypoint. [6](#0-5) [7](#0-6) 

The keeper-facing `controller.update_indexes(caller, assets)` is permissionless and directly forwards to `pool_update_indexes_call`, so any signed caller can trigger the failing accrual; user exits and repayments hit the same panic because they accrue first. [8](#0-7) [9](#0-8) 

### Impact Explanation
This is permanent freezing of user funds, not a transient fail-closed revert: the repository’s own stress test drives a whale 18-decimal market to the cliff and then proves `try_update_indexes`, `try_withdraw`, and `try_repay` all fail with `MathOverflow` while `borrow_index < MAX_BORROW_INDEX_RAY`. [10](#0-9) 

Once crossed, there is no in-scope recovery verb that skips accrual, so suppliers cannot exit, borrowers cannot repay, liquidators cannot close, and `clean_bad_debt`/recapitalization cannot repair the book. [11](#0-10) 

### Likelihood Explanation
Likelihood is bounded by capital and configuration: reaching the cliff requires an extremely large RAY-scaled book plus sustained high-utilization compounding on a steep rate curve. The tested configuration lifts caps to the domain maximum, but `max_cap_for_decimals` permits caps large enough that a `1e36`-RAY position is representable, and `update_indexes` is callable by any authenticated address. [12](#0-11) [8](#0-7) 

The failure is deterministic once `borrowed * borrow_index` or `supplied * supply_index` exceeds `i128::MAX`; smaller chunks only change the timing, because each chunk still evaluates the same overflowing value product. [13](#0-12) 

### Recommendation
Treat total RAY value as an overflow-aware quantity rather than assuming the index cap protects it. Compute `borrowed_original`/`supplied_original` and `borrowed * new_borrow_index` through the existing exact `I256` path and clamp/handle the over-`i128` case explicitly, or enforce an invariant that `max_scaled_position * MAX_BORROW_INDEX_RAY` and `max_scaled_position * MAX_SUPPLY_INDEX_RAY` fit in `i128`. At minimum add an emergency path that can reduce scaled `borrowed`/`supplied` or write down the index without first computing the overflowing total. [14](#0-13) [4](#0-3) 

### Proof of Concept
Use the in-repo scenario in `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap`: create an 18-decimal market on the steep XLM curve, supply `1_000_000_000 * 10^18` base units, borrow 98% of it against sufficient collateral, advance accrual until the index grows past the value ceiling, then call `controller.update_indexes(caller, vec![HubAssetKey { hub_id, asset }])`. The call panics with `MathOverflow` inside `scaled_to_original`/`calculate_supplier_rewards`; subsequent `withdraw` and `repay` panic for the same reason. [15](#0-14) [16](#0-15)

### Citations

**File:** common/src/rates/simulate.rs (L60-69)
```rust
    let borrowed_original = scaled_to_original(env, borrowed, borrow_index);
    let supplied_original = scaled_to_original(env, supplied, supply_index);
    let util = utilization(env, borrowed_original, supplied_original);
    let borrow_rate = calculate_borrow_rate(env, util, params);
    let interest_factor = compound_interest(env, borrow_rate, delta_ms);

    let new_borrow_index = update_borrow_index(env, borrow_index, interest_factor);

    let (supplier_rewards, protocol_fee) =
        calculate_supplier_rewards(env, params, borrowed, new_borrow_index, borrow_index);
```

**File:** common/src/rates/simulate.rs (L157-175)
```rust
    let mut remaining = total_delta_ms;
    while remaining > 0 {
        let chunk = remaining.min(MAX_COMPOUND_DELTA_MS);
        let step = accrue_step(
            env,
            &params,
            state.borrowed,
            supplied,
            borrow_index,
            supply_index,
            chunk,
        );

        borrow_index = step.borrow_index;
        supply_index = step.supply_index;
        supplied = supplied.checked_add(env, step.revenue_shares);

        remaining -= chunk;
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

**File:** common/src/math/fp_core.rs (L14-21)
```rust
/// Widens `x`, `y`, and `d` to `I256` for overflow-safe intermediate arithmetic.
fn to_i256_operands(env: &Env, x: i128, y: i128, d: i128) -> (I256, I256, I256) {
    (
        I256::from_i128(env, x),
        I256::from_i128(env, y),
        I256::from_i128(env, d),
    )
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

**File:** common/src/rates/index.rs (L13-18)
```rust
pub fn update_borrow_index(env: &Env, old_index: Ray, interest_factor: Ray) -> Ray {
    let new_index = old_index.mul(env, interest_factor);
    if new_index.raw() > MAX_BORROW_INDEX_RAY {
        return Ray::from(MAX_BORROW_INDEX_RAY);
    }
    new_index
```

**File:** common/src/rates/index.rs (L80-86)
```rust
    let old_total_debt = borrowed.mul(env, old_borrow_index);
    let new_total_debt = borrowed.mul(env, new_borrow_index);

    let accrued_interest = new_total_debt.checked_sub(env, old_total_debt);

    let protocol_fee = params.reserve_factor.apply_to_ray(env, accrued_interest);
    let supplier_rewards = accrued_interest.checked_sub(env, protocol_fee);
```

**File:** common/src/constants/pool.rs (L18-23)
```rust
/// Ceiling the borrow index is clamped to after growth, in raw ray units.
pub const MAX_BORROW_INDEX_RAY: i128 = 1_000_000_000_000_000_000_000_000_000_000_000_000;

/// Ceiling the supply index is clamped to after growth, in raw ray units.
/// Equal to [`MAX_BORROW_INDEX_RAY`].
pub const MAX_SUPPLY_INDEX_RAY: i128 = MAX_BORROW_INDEX_RAY;
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

**File:** contracts/pool/README.md (L159-168)
```markdown
Each mutation of an existing market runs this sequence:

```text
entrypoint (#[only_owner])
  → Cache::load             # read params + state, bump TTL
  → interest::global_sync   # accrue to now, in ≤1yr chunks
  → mutate                  # cache/shares.rs, cache/cash.rs
  → guards::*               # reserve, utilization, backing checks
  → commit → transfer_out → emit
```
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

**File:** contracts/controller/src/markets.rs (L119-125)
```rust
pub(crate) fn update_indexes(env: &Env, caller: Address, assets: Vec<HubAssetKey>) {
    validation::require_authorized_caller(env, &caller);

    let mut cache = Context::new(env);
    let pool_addr = cache.cached_pool_address();
    pool_update_indexes_call(env, &pool_addr, &assets);
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

**File:** common/src/validation.rs (L48-69)
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
```
