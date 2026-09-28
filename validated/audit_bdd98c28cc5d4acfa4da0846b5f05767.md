### Title
Interest accrual permanently freezes an oversized market when scaled debt exceeds `i128::MAX` - (`common/src/rates/scaling.rs`)

### Summary
Market accrual converts scaled borrow shares into their current value with `scaled_to_original`, which delegates to `Ray::mul` and returns `MathOverflow` when the resulting RAY value does not fit in `i128`. [1](#0-0) [2](#0-1)  `accrue_step` performs this conversion before applying the borrow-index cap, so a sufficiently large market can reach a state where every subsequent accrual reverts even though the stored index is still below `MAX_BORROW_INDEX_RAY`. [3](#0-2) [4](#0-3) 

### Finding Description
Each accrual step first computes `borrowed_original = scaled_to_original(borrowed, borrow_index)` and `supplied_original = scaled_to_original(supplied, supply_index)`. [5](#0-4)  `scaled_to_original` uses `Ray::mul`, which computes `scaled * index / RAY` and raises `GenericError::MathOverflow` if the quotient cannot be represented by `i128`. [1](#0-0) [2](#0-1) 

`update_borrow_index` only clamps the index after multiplying the old index by the interest factor, but that cap is never reached because `accrue_step` panics earlier while valuing the existing scaled balances. [6](#0-5) [7](#0-6)  The same overflow also exists in `calculate_supplier_rewards`, which separately multiplies `borrowed` by the old and new borrow indexes. [8](#0-7) 

The public controller `update_indexes` path reaches the pool’s `update_indexes` operation, which loads the market cache and runs `interest::global_sync` before committing state. [9](#0-8) [10](#0-9)  All state-changing pool operations also accrue before processing their mutation, so the same arithmetic blocks withdrawal, repayment, borrowing, liquidation accounting, and related controller paths once the stored position reaches this state. [11](#0-10) [4](#0-3) 

### Impact Explanation
The affected market becomes permanently unable to accrue interest or complete operations that require accrual. The repository’s regression test demonstrates the condition with a one-billion-token, 18-decimal market at 98% utilization: `update_indexes` fails with `MATH_OVERFLOW` while the stored borrow index remains below its configured cap, and both withdrawal and repayment fail on the same arithmetic. [12](#0-11) 

This permanently freezes supplier principal and yield in the affected market and prevents borrowers or liquidators from settling debt through the normal controller paths. [13](#0-12) [14](#0-13) 

### Likelihood Explanation
Reaching the condition requires unusually large RAY-scaled balances and enough accrual for `scaled_amount * index / RAY` to exceed `i128::MAX`. [1](#0-0) [15](#0-14)  An unprivileged user can create the market state through ordinary `supply` and `borrow` calls if a listed market’s asset decimals, token supply, and configured caps permit the required balances; the exploit does not require control of the pool or controller. [16](#0-15) 

The likelihood is constrained by market capitalization and configured debt/supply limits, but the resulting state is not self-correcting because the overflow occurs before index clamping and before any operation can reduce balances. [17](#0-16) [18](#0-17) 

### Recommendation
Enforce a maximum scaled borrow and supply balance that is derived from the relevant maximum index, so `scaled * index / RAY` is guaranteed to fit in `i128` before shares can be minted. The invariant must cover cumulative `borrowed` and `supplied`, including revenue shares, and should be checked in both supply and borrow share minting rather than relying only on asset-unit caps. [19](#0-18) [20](#0-19) 

If index caps remain in place, perform an explicit pre-accrual representability check before calling `scaled_to_original` and fail earlier at share issuance with a domain-specific cap error instead of allowing the market to enter an unrecoverable state. [6](#0-5) [1](#0-0) 

### Proof of Concept
The repository already contains a deterministic reproduction in `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap`. [21](#0-20) 

1. Configure an 18-decimal market with limits high enough for a one-billion-token position.
2. Supply `1_000_000_000 * 10^18` base units of `BIG18`.
3. Supply sufficient collateral in another market and borrow 98% of `BIG18`.
4. Advance ledger time and call controller `update_indexes` for the `BIG18` hub asset.
5. The call eventually fails with `MATH_OVERFLOW` while `borrow_index < MAX_BORROW_INDEX_RAY`.
6. Subsequent `withdraw` and `repay` calls fail with the same error because they accrue first. [12](#0-11)

### Citations

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

**File:** common/src/rates/simulate.rs (L51-87)
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
    let supplier_shortfall = supply_index_reward_shortfall(
        env,
        supplied,
        supply_index,
        new_supply_index,
        supplier_rewards,
    );

    let protocol_reward = protocol_fee.checked_add(env, supplier_shortfall);
    // Shares are valued at the new supply index, which the caller stores for
    // this step.
    let revenue_shares = if protocol_reward == Ray::ZERO {
        Ray::ZERO
    } else {
        protocol_fee_shares(env, protocol_reward, new_supply_index, supplied)
    };
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

**File:** contracts/pool/src/cache/scale.rs (L30-47)
```rust
    pub(crate) fn calculate_scaled_supply(&self, amount: i128) -> Ray {
        calculate_scaled_supply(
            &self.env,
            amount,
            self.params.asset_decimals,
            self.supply_index,
        )
    }

    /// Converts an asset borrow into scaled debt shares (ceil at the borrow index).
    pub(crate) fn calculate_scaled_borrow(&self, amount: i128) -> Ray {
        calculate_scaled_borrow(
            &self.env,
            amount,
            self.params.asset_decimals,
            self.borrow_index,
        )
    }
```
