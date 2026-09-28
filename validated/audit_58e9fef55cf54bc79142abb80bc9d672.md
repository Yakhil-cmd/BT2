### Title
Accrual panics on `borrowed × borrow_index` overflow before the index cap can engage, permanently freezing the market - (File: common/src/rates/simulate.rs)

### Summary

The bug class is a reachable assertion/abort causing denial of service. The analog is a reachable `MathOverflow` panic inside interest accrual. `accrue_step` computes `borrowed_original = scaled_to_original(env, borrowed, borrow_index)` — an unbounded `Ray::mul` — before any cap is applied [1](#0-0) . The borrow-index ceiling `MAX_BORROW_INDEX_RAY` only clamps `update_borrow_index` output [2](#0-1) , so a large `borrowed` balance multiplied by a grown index overflows `i128` while the index is still far below the cap. Once a market reaches that state, accrual panics on every subsequent call.

### Finding Description

Every pool mutator and the permissionless `update_indexes` run `Cache::load` → `interest::global_sync` → `accrue_chunk` → `accrue_step` before doing anything else [3](#0-2) [4](#0-3) . Inside `accrue_step`, `scaled_to_original` is `scaled.mul(env, index)` [5](#0-4) , which panics with `MathOverflow` when `borrowed.raw() * borrow_index.raw()` exceeds `i128::MAX`. `Ray` values carry 27 decimals, so the product overflows at roughly 1.7e38 — a bound reached by debt value well before `borrow_index` can grow to `MAX_BORROW_INDEX_RAY = 1e36` (i.e., a 1e9× index), because the check ordering never sees the value that would have been clamped. The repository's own harness test `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` demonstrates exactly this: after the panic, `try_withdraw` and `try_repay` both fail with `MATH_OVERFLOW`, and `borrow_index < MAX_BORROW_INDEX_RAY` — "the index cap did not engage before the value overflow" and "the market is frozen: no repay, no withdraw, no liquidation" [6](#0-5) .

### Impact Explanation

Permanent freezing of all funds in the affected `(hub, token)` market: suppliers cannot withdraw, borrowers cannot repay, liquidators cannot seize, `clean_bad_debt`/`recapitalize`/`claim_revenue`/`update_indexes` all panic in accrual. There is no owner escape — pool mutators are `#[only_owner]` = controller-only, and every controller path touching the market accrues first. Supplier deposits and protocol revenue in that book are permanently locked.

### Likelihood Explanation

Requires no privileged access: any unprivileged address builds utilization by `supply`/`borrow` on the controller. The trigger needs a very large book (RAY-scaled `borrowed` near `i128::MAX / borrow_index`) and sustained high utilization over a multi-year horizon, so it is not cheap or fast; but the listed borrow/supply caps only bound token-native amounts (`require_cap_within_asset_domain`), and high-decimal assets make the RAY-scaled product far easier to reach. On Soroban the ledger clock cannot be fast-forwarded, so the attack is realized by waiting — any market with large debt at steep-curve utilization drifts into the cliff monotonically, and once there, the freeze is irreversible.

### Recommendation

Bound the operands before the multiplication: in `accrue_step` (and `Cache::calculate_utilization` in `contracts/pool/src/cache/scale.rs:19-27`), clamp `borrow_index`/`supply_index` to the MAX caps first, and use a saturating/`I256` variant of `mul_div` for `borrowed × index` and `supplied × index` rather than panicking `Ray::mul`. Alternatively, enforce at borrow time that `borrowed * MAX_BORROW_INDEX_RAY` stays within `i128`, making the ceiling unreachable.

### Proof of Concept

`tests/test-harness/tests/controller/large_positions_and_long_horizons.rs` already encodes the attack: seed an 18-decimal market, `supply` ~1e9 × 10^18 units, `borrow` ~98% utilization, then `advance_time(YEAR_SECS)` in a loop calling `update_indexes`; `try_update_indexes` eventually errors `MATH_OVERFLOW` with `borrow_index` below the cap, after which `try_withdraw` and `try_repay` also revert with `MATH_OVERFLOW` [7](#0-6) .

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

**File:** common/src/rates/scaling.rs (L14-16)
```rust
pub fn scaled_to_original(env: &Env, scaled: Ray, index: Ray) -> Ray {
    scaled.mul(env, index)
}
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
