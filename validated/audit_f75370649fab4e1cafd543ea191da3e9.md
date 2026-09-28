### Title
Permanent market freeze when scaled debt or supply times an index exceeds `i128::MAX` - (File: `common/src/rates/simulate.rs`)

### Summary
Every pool market mutation synchronizes interest before processing the requested operation. Synchronization calls `accrue_step`, which unconditionally calculates `borrowed * borrow_index` and `supplied * supply_index` as `Ray` products before applying the configured index ceilings. Once either total crosses the `i128` value ceiling, the multiplication panics with `MathOverflow` instead of being bounded. Because the same synchronization is invoked by `update_indexes`, `repay`, `withdraw`, `borrow`, liquidation paths, `flash_loan`, strategy paths, `claim_revenue`, and `recapitalize`, the market becomes permanently unusable.

### Finding Description
`Controller::update_indexes(caller, assets)` is permissionless apart from caller authorization and forwards `assets` to `pool_update_indexes_call`. [1](#0-0) [2](#0-1) 

On the pool side, `update_indexes` invokes `ops::market::accrue`, which loads each market and calls `interest::global_sync`. [3](#0-2) [4](#0-3) 

`global_sync` chunks elapsed time, but every nonzero chunk calls `accrue_chunk`, which calls `accrue_step`. [5](#0-4) [6](#0-5) 

The root cause is at the start of `accrue_step`: it derives utilization by unscaling both market totals with `scaled_to_original` before calculating the next index. [7](#0-6) 

`scaled_to_original` delegates to `Ray::mul`, which calls `mul_div_half_up`; that function panics with `GenericError::MathOverflow` when the exact result cannot fit in `i128`. [8](#0-7) [9](#0-8) [10](#0-9) 

The index cap does not prevent this state: `update_borrow_index` caps only the resulting index, while `accrue_step` has already multiplied the scaled balance by the index. [11](#0-10) [12](#0-11) 

All normal exit operations inherit the same trap because `ops::load_leg` calls `synced_market`, and `synced_market` always performs `global_sync` before the leg-specific accounting. [13](#0-12) 

For example, `repay` calls `ops::load_leg` before resolving or burning debt, and `withdraw` does the same before resolving or burning supply. [14](#0-13) [15](#0-14) 

### Impact Explanation
This is a permanent freezing of funds and a market liveness failure. Once `borrowed * borrow_index > i128::MAX` or `supplied * supply_index > i128::MAX`, no later operation can clear the condition because the panic occurs while calculating current totals, before debt can be repaid, supply can be burned, bad debt can be socialized, or indexes can be replaced.

The repository already contains a regression demonstrating this boundary. It creates a one-billion-token, 18-decimal market at 98% utilization, advances time until `update_indexes` fails with `MATH_OVERFLOW`, and then verifies that both a withdrawal and repayment fail with the same error. [16](#0-15) 

### Likelihood Explanation
Triggering the condition requires a very large market or an asset-decimals configuration that produces a large RAY-denominated scaled balance, followed by sustained interest growth. No privileged action is needed at trigger time: an unprivileged caller can submit `Controller::update_indexes(attacker_or_any_caller, vec![hub_asset])`.

The likelihood is lower than an ordinary input-validation DoS because constructing the state requires substantial liquidity and sustained utilization. Nevertheless, the code supports arbitrary listed token decimals and large balances, and the affected arithmetic is a market-wide accounting boundary rather than a per-request resource limit. Once reached, the failure is deterministic and cannot be avoided by splitting the elapsed interval because the panic occurs inside the first compounding chunk.

### Recommendation
Do not compute full `scaled * index` market values in a representation bounded by `i128` before enforcing index ceilings. Rework accrual to use saturating or checked projections for utilization and debt-value deltas, or move the relevant totals to a wider internal representation and only convert to `i128` after applying a proven bound.

At minimum:

- Make `accrue_step` handle an over-range current supplied/borrowed value without panicking.
- Enforce `MAX_BORROW_INDEX_RAY` and `MAX_SUPPLY_INDEX_RAY` before producing an over-range product.
- Add explicit market-state guards that keep `scaled_amount * index` within the supported domain.
- Add regression tests covering `scaled * index` just below, exactly at, and above `i128::MAX`.
- Verify that repayment, withdrawal, liquidation, bad-debt cleanup, and parameter replacement remain executable after index saturation.

### Proof of Concept
A concrete flow is already encoded by `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap`:

1. Create an 18-decimal market using the steep XLM rate curve and a collateral market.
2. Supplier `BOB` supplies `1_000_000_000 * 10^18` units of `BIG18`.
3. `ALICE` supplies sufficient collateral and borrows 98% of the `BIG18` market.
4. Advance ledger time until the next permissionless `update_indexes` call fails.
5. Submit `Controller::update_indexes(caller, vec![HubAssetKey { hub_id, asset: BIG18 }])`.
6. The pool reaches `accrue_step`, where `scaled_to_original(borrowed, borrow_index)` overflows and returns `MathOverflow`.
7. Subsequent `repay` and `withdraw` calls fail before their operation-specific logic because both load a synced market.

The regression confirms that the stored borrow index remains below `MAX_BORROW_INDEX_RAY`, proving the index cap never engages before the total-value overflow. [17](#0-16)

### Citations

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

**File:** common/src/constants/pool.rs (L18-23)
```rust
/// Ceiling the borrow index is clamped to after growth, in raw ray units.
pub const MAX_BORROW_INDEX_RAY: i128 = 1_000_000_000_000_000_000_000_000_000_000_000_000;

/// Ceiling the supply index is clamped to after growth, in raw ray units.
/// Equal to [`MAX_BORROW_INDEX_RAY`].
pub const MAX_SUPPLY_INDEX_RAY: i128 = MAX_BORROW_INDEX_RAY;
```

**File:** contracts/pool/src/ops/mod.rs (L29-47)
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
}
```

**File:** contracts/pool/src/ops/repay.rs (L40-47)
```rust
pub(crate) fn accounting(env: &Env, action: &PoolAction) -> RepayOutcome {
    let (mut cache, position) = ops::load_leg(env, action);
    let amount = action.amount;

    let (burned, overpayment) = cache.resolve_repay(amount, position);
    let net_repay = amount
        .checked_sub(overpayment)
        .unwrap_or_else(|| panic_with_error!(env, GenericError::MathOverflow));
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
