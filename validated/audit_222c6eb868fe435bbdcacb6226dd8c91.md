### Title
Sustained high utilization drives `borrowed * borrow_index` past i128 inside accrual, permanently freezing all exits and repayments on the market - ([File: common/src/rates/scaling.rs])

### Summary
Every accrual step in `accrue_step` starts by unscaling the market's scaled debt and scaled supply with `scaled_to_original`, which uses the panicking `Ray::mul` (`mul_div_half_up` → `GenericError::MathOverflow`). The borrow index is capped at `MAX_BORROW_INDEX_RAY` (10^36), but the *product* `borrowed_ray * borrow_index / RAY` overflows i128 far earlier — around a 170x index for a whale-scale market. Once that line is crossed, every entrypoint that accrues first (`update_indexes`, `withdraw`, `repay`, `borrow`, `liquidate`, `clean_bad_debt`, `claim_revenue`) traps, and the trap is permanent: `last_timestamp` never advances, so no later call can skip accrual. `common/src/rates/scaling.rs:14-16`, `common/src/rates/simulate.rs:60-61`, `contracts/pool/src/interest.rs:26-32` [1](#0-0) [2](#0-1) [3](#0-2) 

### Finding Description
The CVE class is a crash/warning reachable on an attacker-constructible input. Here the attacker-constructible input is market state: `borrowed` (scaled) and `borrow_index` are both driven by ordinary unprivileged actions. A single address can `supply` a large amount of a high-decimals token (the admitted cap for an 18-decimal asset is `i128::MAX / 10^9` ≈ 1.7e29 raw units, per `require_cap_within_asset_domain`/`max_cap_for_decimals`), `borrow` near `max_utilization` through a spoke, and then let time accrue. Because debt compounds faster than supply books rewards, utilization drifts upward until the rate sits at the steep segment of the curve; `update_borrow_index` clamps the index at 10^36 but multiplies before clamping, and `scaled_to_original(borrowed, borrow_index)` has no ceiling — it panics on overflow before the index cap ever engages. The harness test `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` demonstrates exactly this: after several years at 98% utilization on a steep curve, `update_indexes` fails with `MATH_OVERFLOW`, and subsequent `withdraw` and `repay` fail identically because every verb accrues first. `common/src/validation.rs:48-70`, `common/src/rates/index.rs` (update_borrow_index), `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:320-360` [4](#0-3) [5](#0-4) 

Notably the saturating variant `mul_div_floor_saturating` already exists in `fp_core` and is used elsewhere (`calculate_scaled_cap`, `update_supply_index`, `protocol_fee_shares`) precisely so these paths fail open instead of trapping — `scaled_to_original` inside accrual is the un-saturated exception. `common/src/math/fp_core.rs:180-201`, `common/src/rates/scaling.rs:26-33` [6](#0-5) 

### Impact Explanation
Permanent freezing of funds: once the cliff is reached, no supplier can `withdraw`, no borrower can `repay`, no liquidator can `liquidate`, and `clean_bad_debt`/`recapitalize`/`claim_revenue` all accrue first and trap on the same multiplication. There is no governance escape hatch that skips accrual — `update_params` also accrues on the old curve first. The entire market book is bricked while the pool contract still custodies the underlying tokens. A whale attacker who supplied most of the market loses their own funds too, but if the market is shared, all other suppliers' and revenue claims freeze permanently with them. [3](#0-2) 

### Likelihood Explanation
Medium. The attacker needs (a) a listed market whose governance-set caps admit ~10^29-scale raw positions (permitted by `max_cap_for_decimals` for high-decimal assets), (b) the capital to supply and borrow that much, and (c) sustained high utilization for multiple years so the borrow index approaches ~170x — at the 200% APR ceiling that is on the order of several years, faster on steep curves since utilization self-amplifies. No privileged call is needed: `supply`, `borrow`, and the permissionless `update_indexes` are all unprivileged, and any third party's later accrual-triggering call completes the freeze. The docs acknowledge the limit ("value overflow can occur before the index ceiling and block repayment/withdrawal", `docs/reference/formulas.md:433-437`), which bounds the severity but does not mitigate the permanence. [7](#0-6) 

### Recommendation
Make the accrual path saturate or clamp instead of panicking, mirroring the kernel fix's "remove the trap on expected input" shape:

- In `accrue_step` (`common/src/rates/simulate.rs:60-61`), compute `borrowed_original`/`supplied_original` with a saturating `mul` (e.g. `mul_div_floor_saturating`-backed `Ray` mul), and treat a saturated debt value as `borrow_index = MAX_BORROW_INDEX_RAY` with zero further interest — the same terminal state the index cap already produces.
- Alternatively, short-circuit accrual when `borrow_index == MAX_BORROW_INDEX_RAY` or when `borrowed` exceeds `i128::MAX / borrow_index` before multiplying.
- Ensure `update_indexes` can always make forward progress so liquidation and `clean_bad_debt` remain reachable even in the saturated regime.

### Proof of Concept
Pinned by the existing harness test `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` (`tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:320-361`):

1. List an 18-decimal asset with a steep curve (175% max borrow rate) and a cap near the admitted maximum.
2. `supply` ~10^9 whole tokens; `borrow` 98% of it through a separate collateralized account — all unprivileged calls.
3. Advance ledger time in yearly steps while calling `update_indexes` (permissionless).
4. Once `borrowed * borrow_index` exceeds the i128 RAY product bound — before `borrow_index` reaches `MAX_BORROW_INDEX_RAY` — `update_indexes` returns `Error(Contract, MATH_OVERFLOW)` (`#33`), and `try_withdraw`/`try_repay` fail with the same error on every subsequent attempt. The market, including other suppliers' shares and accrued protocol revenue, is permanently frozen. [8](#0-7)

### Citations

**File:** common/src/rates/scaling.rs (L14-16)
```rust
pub fn scaled_to_original(env: &Env, scaled: Ray, index: Ray) -> Ray {
    scaled.mul(env, index)
}
```

**File:** common/src/rates/simulate.rs (L60-66)
```rust
    let borrowed_original = scaled_to_original(env, borrowed, borrow_index);
    let supplied_original = scaled_to_original(env, supplied, supply_index);
    let util = utilization(env, borrowed_original, supplied_original);
    let borrow_rate = calculate_borrow_rate(env, util, params);
    let interest_factor = compound_interest(env, borrow_rate, delta_ms);

    let new_borrow_index = update_borrow_index(env, borrow_index, interest_factor);
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

**File:** common/src/validation.rs (L48-70)
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
}
```

**File:** tests/test-harness/tests/controller/large_positions_and_long_horizons.rs (L316-360)
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
```

**File:** common/src/math/fp_core.rs (L180-201)
```rust
pub fn mul_div_floor_saturating(env: &Env, x: i128, y: i128, d: i128) -> i128 {
    require_nonzero_divisor(env, d);
    if let Some(quotient) = x
        .checked_mul(y)
        .and_then(|product| div_floor_i128(product, d))
    {
        return quotient;
    }
    let (x256, y256, d256) = to_i256_operands(env, x, y, d);
    div_floor_i256(
        env,
        &x256.mul(&y256),
        &d256,
        quotient_is_nonnegative(x, y, d),
    )
    .to_i128()
    .unwrap_or(if quotient_is_negative(x, y, d) {
        i128::MIN
    } else {
        i128::MAX
    })
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
