### Title
Accrual-time `i128` value overflow traps every market verb and permanently freezes supplier funds — (File: common/src/rates/index.rs)

### Summary
The crash class of CVE-2024-48426 (an invalid-memory-read panic found by fuzzing) maps onto Soroban as a host arithmetic trap reachable on a normal entry path. In XOXNO Lending, every state-changing pool op runs `interest::global_sync` first, and `global_sync` → `accrue_step` → `calculate_supplier_rewards` evaluates `borrowed.mul(new_borrow_index)` — a `shares × index` product that must fit `i128`. On a large, highly-utilized market this product overflows before the borrow index reaches `MAX_BORROW_INDEX_RAY`, so accrual panics with `MathOverflow` forever: `update_indexes`, `repay`, `withdraw`, `borrow`, `liquidate` (via seizure/withdrawal), and `claim_revenue` all revert on that market. The dedicated harness test demonstrates the cliff: below `MAX_BORROW_INDEX_RAY`, `try_update_indexes_for`, `try_withdraw_raw` and `try_repay` all fail with `MATH_OVERFLOW`.

### Finding Description
Accrual computes debt growth with `old_total_debt = borrowed.mul(old_index)` and `new_total_debt = borrowed.mul(new_index)` in `calculate_supplier_rewards` [1](#0-0) . `Ray::mul` is exact (`I256` fallback) but the result must fit `i128`; when `borrowed_raw * index_raw / RAY > i128::MAX` it panics with `GenericError::MathOverflow` [2](#0-1) . The same bound applies to `supplied.mul(old_index)` in `update_supply_index` [3](#0-2)  and to `scaled_to_original` used for utilization [4](#0-3) .

`global_sync` runs before every mutation of a market (`Cache::load` → `interest::global_sync` → mutate) [5](#0-4) , so once the debt value crosses the `i128` RAY ceiling the panic is hit by every verb. The borrow-index cap at `MAX_BORROW_INDEX_RAY` (10^36) never engages because the panic occurs in the value computation, not the index write [6](#0-5) . The protocol's own docs acknowledge "value overflow can occur before the index ceiling and block repayment/withdrawal because those operations accrue first" [7](#0-6) , and `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs::a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` proves it end-to-end [8](#0-7) .

An unprivileged address reaches this state through ordinary verbs: `supply` a high-decimals asset up to the admitted cap (~170 billion whole tokens for 18 decimals, per `max_cap_for_decimals`), `borrow` ~98% of it against collateral in another market, then wait while anyone calls the permissionless keeper `update_indexes(caller, assets)` [9](#0-8) . At sustained steep-curve rates the index grows ~170x in a few years and the next accrual — callable by anyone — trips the trap permanently. `last_timestamp` is never stamped past the failing chunk, so no future call can skip the overflowing window.

### Impact Explanation
Permanent freezing of funds for every supplier and borrower in the affected market: no withdraw, repay, liquidate, seize, `claim_revenue`, or `recapitalize` can execute because each accrues first and panics. Deposited principal is unrecoverable; `clean_bad_debt` cannot run either, so even socialized exit is impossible. This is not fail-closed-on-bad-input — all inputs are valid; it is an arithmetic ceiling in the accrual path itself.

### Likelihood Explanation
Requires a whale-scale position (near the admitted cap) on a high-decimals market at sustained high utilization, plus years of accrual at the steep curve segment — or faster if a market lists an extreme curve. No privileged action is needed to create the state (any user can supply/borrow to cap and anyone can call `update_indexes`), but the capital requirement and accrual time make deliberate triggering expensive and accidental triggering plausible only for very large markets. Medium.

### Recommendation
Saturate rather than panic in the accrual value computations: use `mul_div_floor_saturating`-style clamping (already used by `update_supply_index` and `protocol_fee_shares`) when valuing `borrowed * index`, or clamp `new_borrow_index` to the largest index for which `borrowed * index / RAY` still fits `i128` before valuing. Alternatively, make `global_sync` stamp `last_timestamp` per successfully committed chunk so progress is preserved, and enforce tighter `require_cap_within_asset_domain`-style caps at listing so `cap × MAX_BORROW_INDEX_RAY / RAY` provably fits `i128` — currently caps bound the input conversion only, not accrued value [10](#0-9) .

### Proof of Concept
The repository contains an executable demonstration. `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:320-361`: list `BIG18` (18 decimals, XLM curve), lift caps, supply `10^9 × 10^18` units, borrow 98%, advance time year-by-year calling `update_indexes`. Within 40 simulated years `try_update_indexes_for` returns `MATH_OVERFLOW` while `borrow_index < MAX_BORROW_INDEX_RAY`, and both `try_withdraw_raw(BOB, "BIG18", 1)` and `try_repay(ALICE, "BIG18", 1.0)` revert with `MATH_OVERFLOW` — the market is permanently frozen.

### Citations

**File:** common/src/rates/index.rs (L13-19)
```rust
pub fn update_borrow_index(env: &Env, old_index: Ray, interest_factor: Ray) -> Ray {
    let new_index = old_index.mul(env, interest_factor);
    if new_index.raw() > MAX_BORROW_INDEX_RAY {
        return Ray::from(MAX_BORROW_INDEX_RAY);
    }
    new_index
}
```

**File:** common/src/rates/index.rs (L34-34)
```rust
    let total_supplied_value = supplied.mul(env, old_index);
```

**File:** common/src/rates/index.rs (L80-83)
```rust
    let old_total_debt = borrowed.mul(env, old_borrow_index);
    let new_total_debt = borrowed.mul(env, new_borrow_index);

    let accrued_interest = new_total_debt.checked_sub(env, old_total_debt);
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

**File:** docs/reference/formulas.md (L432-437)
```markdown
The token-to-RAY maximum is also the admitted cap maximum. Accrued position
values and market totals must independently fit the RAY domain; valid caps and
bounded indexes do not guarantee that future accrual fits. Value overflow can
occur before the index ceiling and block repayment/withdrawal because those
operations accrue first. At the borrow-index ceiling, further accrual produces
no borrower interest. No dedicated ceiling alarm is emitted.
```

**File:** tests/test-harness/tests/controller/large_positions_and_long_horizons.rs (L320-361)
```rust
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
    std::println!(
        "ray-value cliff reached after {years} years at 98 percent utilization on the XLM curve; last index x{:.1}",
        last.borrow_index as f64 / RAY as f64
    );
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
