### Title
RAY-denominated market totals can overflow during interest accrual and permanently freeze a market - (File: common/src/rates/simulate.rs)

### Summary
An unprivileged user can trigger an unchecked fixed-point domain boundary by growing a market until `scaled_amount * index` no longer fits in `i128`. The permissionless `Controller::update_indexes` path then panics in `accrue_step`, and because every pool mutation accrues first, subsequent repayment, withdrawal, and liquidation attempts fail with `MathOverflow`.

### Finding Description
`accrue_step` materializes both market totals with `scaled_to_original` before calculating utilization. [1](#0-0)  `scaled_to_original` calls `Ray::mul`, which ultimately panics with `GenericError::MathOverflow` when the exact product does not fit in `i128`. [2](#0-1) [3](#0-2) 

The permissionless controller entrypoint forwards caller-selected `HubAssetKey`s to the pool. [4](#0-3) [5](#0-4)  Pool `update_indexes` loads each market and executes `interest::global_sync`. [6](#0-5)  That sync calls the same fallible `accrue_step` before updating `last_timestamp`; therefore the panic occurs before any safe partial accrual is committed. [7](#0-6) 

The borrow-index cap does not prevent this condition because it is applied only after the overflowing market-value calculation. [8](#0-7) 

### Impact Explanation
This permanently freezes the affected market rather than merely rejecting one crafted transaction. Once `scaled * index` crosses the `i128` boundary, every later sync attempts the same product and panics before `mark_accrued` runs. Because repay, withdrawal, liquidation, recapitalization, and other market mutations run through the same accrual path, suppliers cannot exit and borrowers or liquidators cannot reduce debt. The repository’s regression test demonstrates that withdrawal and repayment both subsequently fail with `MathOverflow`. [9](#0-8) 

This is permanent freezing of user funds and can leave protocol debt unliquidatable. Recovery would require privileged intervention or a code upgrade; no ordinary user path can bypass the accrual panic.

### Likelihood Explanation
The attack path is unprivileged: supply through `Controller::supply`, borrow through `Controller::borrow`, allow interest to accrue, and call `Controller::update_indexes`. The attacker must first create an exceptionally large market and sustain high utilization until the index multiplier crosses the value ceiling. That requires substantial capital and an allowed market/cap configuration, so exploitation is conditional rather than universally available.

The in-repository PoC uses one billion 18-decimal tokens, 98% utilization, and the XLM rate curve; repeated annual `update_indexes` calls reach `MathOverflow` below the configured borrow-index cap. [10](#0-9) 

### Recommendation
Do not materialize unchecked RAY-valued market totals during routine accrual. In `accrue_step` / `calculate_supplier_rewards`:

- Compute accrued debt as `borrowed * (new_index - old_index)` instead of subtracting two separately materialized `borrowed * index` products.
- Compute utilization through an overflow-safe quotient or widened `I256` arithmetic rather than requiring both absolute RAY values to fit `i128`.
- Apply the borrow-index ceiling before operations that can overflow.
- Consider enforcing a market-size invariant at supply/borrow entry that preserves enough arithmetic headroom for the maximum supported index.
- Add a regression test proving that after the index reaches its ceiling, repay, withdraw, liquidation, and recapitalization remain executable.

### Proof of Concept
The repository already contains a deterministic state-level PoC in `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap`:

```rust
let principal = BILLION * 10i128.pow(18);
t.supply_raw(BOB, "BIG18", principal);
let debt = principal / 100 * 98;
t.borrow_raw(ALICE, "BIG18", debt);

loop {
    t.advance_time(YEAR_SECS);
    if let Err(e) = t.try_update_indexes_for(&["BIG18"]) {
        break e;
    }
}

assert_contract_error(t.try_withdraw_raw(BOB, "BIG18", 1), errors::MATH_OVERFLOW);
assert_contract_error(t.try_repay(ALICE, "BIG18", 1.0), errors::MATH_OVERFLOW);
```

The test confirms the index cap never engages before the overflow and that both exit and repayment are subsequently blocked. [9](#0-8)

### Citations

**File:** common/src/rates/simulate.rs (L51-63)
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
```

**File:** common/src/rates/scaling.rs (L12-16)
```rust
/// Converts a scaled `Ray` amount to its original (unscaled) value by
/// multiplying by `index`, rounding half up.
pub fn scaled_to_original(env: &Env, scaled: Ray, index: Ray) -> Ray {
    scaled.mul(env, index)
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

**File:** common/src/rates/index.rs (L13-18)
```rust
pub fn update_borrow_index(env: &Env, old_index: Ray, interest_factor: Ray) -> Ray {
    let new_index = old_index.mul(env, interest_factor);
    if new_index.raw() > MAX_BORROW_INDEX_RAY {
        return Ray::from(MAX_BORROW_INDEX_RAY);
    }
    new_index
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
