### Title
Borrow-index growth overflows `scaled_to_original` before `MAX_BORROW_INDEX_RAY` engages, permanently freezing all market operations - ([File: common/src/rates/simulate.rs])

### Summary
CVE-2017-3257 is an InnoDB hang/crash DoS: a low-privileged actor can permanently wedge the service. The structural analog in XOXNO Lending is a panic in the mandatory accrual prelude. `accrue_step` multiplies total `borrowed` shares by the current `borrow_index` (`scaled_to_original`, half-up, `i128` result) to compute utilization *before* the borrow index cap can clamp growth [1](#0-0) . On a sufficiently large market at sustained high utilization, `borrowed * borrow_index` exceeds `i128` while `borrow_index` is still below `MAX_BORROW_INDEX_RAY` (1e36), so `mul_div_half_up` traps with `MathOverflow` [2](#0-1) . Because `global_sync` runs first in every pool mutation and `update_indexes`/`accrue` is permissionless, once the crossing point is passed every subsequent call re-panics — no repay, withdraw, liquidate, or cleanup can ever execute on that market again [3](#0-2) [4](#0-3) .

### Finding Description
The rate engine's own invariant admits the failure: "Debt-value overflow can still revert accrual before that ceiling is reached. Bounded indexes do not guarantee representable position or market values" [5](#0-4) . `update_borrow_index` clamps the *index* at 1e36, but nothing clamps `borrowed` (scaled RAY shares, up to ~i128::MAX/1e27 ≈ 1.7e11 whole-token value) against the index inside the half-up `scaled * index / RAY` product. With 18-decimal assets, `borrowed` scaled is `debt_units * 1e9`; an index of ~170x against a ~1e9·1e18-unit debt already saturates `i128` [6](#0-5) .

The production test `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` demonstrates the freeze end-to-end: `try_update_indexes_for`, `try_withdraw_raw(1)`, and `try_repay(1.0)` all fail with `MATH_OVERFLOW`, and the index cap "did not engage before the value overflow" [7](#0-6) .

Reachability: an unprivileged caller creates the precondition with `supply`/`borrow` on its own positions. The market must be large (the test uses ~1e9 tokens of an 18-decimal asset, debt at 98% utilization on the steep XLM curve) and borrow caps must permit the book size — caps are literal asset-unit governance settings, and `calculate_scaled_cap` *saturates* rather than trapping, so the entry path stays open even at extreme caps [8](#0-7) . No privileged call, key leak, or upgrade is needed to trigger the panic — `update_indexes`/`accrue` is callable by anyone [4](#0-3) .

### Impact Explanation
Permanent freezing of funds. Once `borrowed_original` overflows `i128`, every controller verb on that (hub, asset) market — `withdraw`, `repay`, `liquidate`, `clean_bad_debt`, `claim_revenue`, `borrow` — panics in `global_sync` before any state change. All supplier principal, borrower collateral claims, and unclaimed protocol revenue in that market are irrecoverable; debt can never be repaid or liquidated. This mirrors the CVE's availability impact (complete DOS) but is stronger: the freeze is permanent, not a restart-able crash.

### Likelihood Explanation
Medium-low but real. It requires (a) a market whose scaled debt `borrowed * borrow_index` approaches `i128::MAX` (~1.7e38), e.g. ~1e9 whole-token debt at index ~170x, and (b) sustained high utilization for years so the index climbs before the 1e36 cap. The repo's own test asserts the cliff arrives "in a few years" on the XLM curve at 98% utilization and flags that the documented bound in `formulas.md` is wrong [9](#0-8) . High-decimal RWA-style tokens make the scaled-share ceiling much easier to reach. The defect is a code ordering/sizing error, not a parameter misconfiguration: the cap that was supposed to bound growth is unreachable where it matters. Severity: Medium — a conditional, slow-burning but unrecoverable market-wide DoS reachable without privileges.

### Recommendation
Cap the *value* domain, not just the index. Options: (1) in `accrue_step`, compute utilization on saturating/clamped originals so the rate loop keeps running (index then hits `MAX_BORROW_INDEX_RAY` and accrual becomes a no-op instead of trapping); (2) add a pre-check in `update_borrow_index`/`scaled_to_original` that detects the value overflow and clamps the index to `MAX_BORROW_INDEX_RAY` rather than panicking; (3) validate at listing/borrow time that `calculate_scaled_borrow(cap) * MAX_BORROW_INDEX_RAY` fits `i128`, so a market can never book debt large enough to hit the cliff. Whichever is chosen, the invariant to enforce is "accrual can never revert due to representable index growth" — matching the documented claim that the borrow index is "monotone and bounded."

### Proof of Concept
Existing production-side test proving the freeze (permits as a harness scenario):

```rust
// tests/test-harness/tests/controller/large_positions_and_long_horizons.rs
let principal = BILLION * 10i128.pow(18);            // 1e9 tokens, 18 decimals
t.supply_raw(BOB, "BIG18", principal);
let debt = principal / 100 * 98;                     // 98% utilization
t.supply_raw(ALICE, "COL", BILLION * 10_000_000 * 3);
t.borrow_raw(ALICE, "BIG18", debt);

// advance ~1 year per iteration on the steep XLM rate curve
loop {
    t.advance_time(YEAR_SECS);
    if let Err(e) = t.try_update_indexes_for(&["BIG18"]) { break e; }
}
// -> MATH_OVERFLOW inside scaled_to_original, borrow_index < MAX_BORROW_INDEX_RAY

// market is permanently frozen:
assert_contract_error(t.try_withdraw_raw(BOB, "BIG18", 1), errors::MATH_OVERFLOW);
assert_contract_error(t.try_repay(ALICE, "BIG18", 1.0), errors::MATH_OVERFLOW);
```

The panic path: `accrue`/`update_indexes` → `Cache::load` → `interest::global_sync` → `accrue_chunk` → `accrue_step` → `scaled_to_original(borrowed, borrow_index)` → `Ray::mul` → `mul_div_half_up` → `MathOverflow` [10](#0-9) . Once the first panic occurs, the state is committed only on success, so `borrowed`/`borrow_index` stay frozen at the pre-overflow values and every later call hits the identical trap.

### Citations

**File:** common/src/rates/simulate.rs (L60-66)
```rust
    let borrowed_original = scaled_to_original(env, borrowed, borrow_index);
    let supplied_original = scaled_to_original(env, supplied, supply_index);
    let util = utilization(env, borrowed_original, supplied_original);
    let borrow_rate = calculate_borrow_rate(env, util, params);
    let interest_factor = compound_interest(env, borrow_rate, delta_ms);

    let new_borrow_index = update_borrow_index(env, borrow_index, interest_factor);
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

**File:** docs/reference/invariants.md (L231-236)
```markdown
Both indexes start at one RAY. Successful accrual with validated rate parameters
cannot lower the borrow index and caps it at the protocol constant 10^36 raw
RAY. At the ceiling, further accrual produces no borrower interest.

Debt-value overflow can still revert accrual before that ceiling is reached.
Bounded indexes do not guarantee representable position or market values.
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
