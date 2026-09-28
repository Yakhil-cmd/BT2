### Title
Overflow in `supplied * supply_index` during accrual permanently freezes a market, locking all supplier funds - (File: common/src/rates/index.rs)

### Summary
The analog of "strike price × amount overflows and the receiver can never reclaim" is the market-level product `supplied × supply_index` (and `borrowed × borrow_index`) computed on every accrual. In the OTLM report, a user-chosen parameter (strike price) makes the reclaim path revert forever; here, an unprivileged user can push `supplied` large enough via `controller::supply` that the fixed-point multiply inside `update_supply_index` / `scaled_to_original` overflows `i128`, panics with `MathOverflow`, and permanently freezes the entire market — no withdraw, repay, or liquidation can ever execute again.

### Finding Description
Every mutating pool operation runs `global_sync` first, which calls `accrue_step`, which computes `scaled_to_original(supplied, supply_index)` and `update_supply_index(supplied, old_index, rewards)` — both of which evaluate `supplied.mul(env, index)` [1](#0-0) [2](#0-1) . `Ray::mul` panics with `GenericError::MathOverflow` when the result leaves `i128` [3](#0-2) .

Unlike the OTLM `amount * strikePrice`, nothing bounds `supplied` relative to the index domain. `require_cap_within_asset_domain` admits caps up to `i128::MAX / 10^(27-d)` in asset units — i.e., scaled `supplied` can approach `i128::MAX` itself (≈170 billion whole tokens per docs) [4](#0-3) . Additionally, `protocol_fee_shares` mints revenue shares into `supplied` that are not subject to any cap check [5](#0-4) . Once `supplied × supply_index / RAY` exceeds `i128::MAX`, every accrual panics, and since every verb accrues first, the freeze is unrecoverable — even `withdraw` cannot reduce `supplied` because it must accrue before resolving shares. The codebase's own test demonstrates this freeze end state [6](#0-5) .

### Impact Explanation
Permanent freezing of funds: once `supplied.mul(supply_index)` (or `borrowed.mul(borrow_index)`) overflows, `update_indexes`, `supply`, `withdraw`, `repay`, `liquidate`, `clean_bad_debt`, and every flash/strategy path on that (hub, token) market revert. All tokens held by the pool for that market — every supplier's principal plus unclaimed revenue — are locked permanently, matching the OTLM "receiver cannot reclaim" impact at market scale.

### Likelihood Explanation
Reachable by a single unprivileged address on any market whose admitted supply cap permits a large position: the attacker calls `controller::supply` with an amount near the token-to-RAY input maximum (cap permitting — caps saturate fail-open via `calculate_scaled_cap` at sub-1 indices, per `scaling.rs`) [7](#0-6) . As the supply index drifts above `RAY` through normal accrual (or as revenue shares inflate `supplied`), the product crosses the `i128` ceiling and the next accrual-triggering call bricks the market. The docs concede the gap: "valid caps and bounded indexes do not guarantee that future accrual fits. Value overflow can occur before the index ceiling and block repayment/withdrawal" [8](#0-7) . The main cost caveat is that the attacker must actually supply (or borrow) near-cap size; the freeze then harms all other suppliers.

### Recommendation
Enforce the market-value invariant at entry rather than treating overflow as an accepted arithmetic limit:
- In the supply/borrow cap check (controller `spoke_usage` / `validation::require_cap_within_asset_domain`), reject admissions where `scaled * MAX_SUPPLY_INDEX_RAY / RAY` exceeds `i128::MAX` — i.e., cap the scaled exposure so that the product stays in-domain even at the index ceiling.
- Alternatively, make `update_supply_index` and `scaled_to_original` used in accrual saturate/short-circuit like `mul_div_floor_saturating` does for caps, and mint no further revenue shares once `supplied` is within a margin of the overflow bound, so accrual remains monotone and exits never brick.
- At minimum, gate revenue-share minting in `add_protocol_revenue`/`accrue_step` on `supplied + fee_scaled` staying below the overflow-safe bound, since revenue shares bypass the cap check entirely.

### Proof of Concept
```rust
// Conceptual Soroban test (test-harness style):
// BIG18 market, cap lifted to max_cap_for_decimals(18), index already > RAY
// after some accrual (any nonzero borrow interest suffices).

let principal = /* amount such that scaled shares ~ i128::MAX */;
// scaled = principal * 10^(27-18) ≈ i128::MAX  =>  supplied * supply_index / RAY
// overflows i128 once supply_index > RAY.
t.supply_raw(ATTACKER, "BIG18", principal);   // succeeds if rewards accrue as zero on entry
t.supply_raw(VICTIM, "BIG18", 1_000.0);        // victim liquidity now trapped

// Any subsequent accrual-triggering entry point reverts with MathOverflow:
assert_contract_error(t.try_withdraw_raw(VICTIM, "BIG18", 1), errors::MATH_OVERFLOW);
assert_contract_error(t.try_repay(ALICE, "BIG18", 1.0), errors::MATH_OVERFLOW);
assert_contract_error(t.try_update_indexes_for(&["BIG18"]), errors::MATH_OVERFLOW);
// Pool tokens for BIG18 are permanently locked — mirrors
// a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap
```
Root cause: `update_supply_index` line `let total_supplied_value = supplied.mul(env, old_index);` and `accrue_step`'s `scaled_to_original(env, supplied, supply_index)` panic on `i128` overflow, and no admission check keeps `supplied` below `i128::MAX * RAY / supply_index_ceiling` [9](#0-8) [10](#0-9) .

### Citations

**File:** contracts/pool/src/interest.rs (L39-53)
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
}
```

**File:** contracts/pool/src/interest.rs (L59-66)
```rust
pub(crate) fn add_protocol_revenue(cache: &mut Cache, fee: Ray) {
    if fee == Ray::ZERO {
        return;
    }

    let fee_scaled = protocol_fee_shares(cache.env(), fee, cache.supply_index(), cache.supplied());
    cache.accrue_revenue(fee_scaled);
}
```

**File:** common/src/rates/simulate.rs (L60-71)
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
```

**File:** common/src/math/fp_core.rs (L145-159)
```rust
/// Computes `floor(x * y / d)`, rounding toward negative infinity for a negative quotient.
/// Panics with `GenericError::DivisionByZero` if `d == 0`, or with
/// `GenericError::MathOverflow` if the result does not fit in `i128`.
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
}
```

**File:** docs/reference/formulas.md (L425-437)
```markdown
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

**File:** tests/test-harness/tests/controller/large_positions_and_long_horizons.rs (L316-361)
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
    std::println!(
        "ray-value cliff reached after {years} years at 98 percent utilization on the XLM curve; last index x{:.1}",
        last.borrow_index as f64 / RAY as f64
    );
}
```

**File:** common/src/rates/scaling.rs (L14-16)
```rust
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

**File:** common/src/rates/index.rs (L29-45)
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
}
```
