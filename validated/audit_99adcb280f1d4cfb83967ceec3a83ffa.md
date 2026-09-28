### Title
Accrual value overflow permanently freezes an oversized market - ([File: common/src/rates/scaling.rs](common/src/rates/scaling.rs))

### Summary

An oversized supply or debt share balance can make `scaled_to_original` overflow `i128` before the borrow-index ceiling engages. Because `Controller::update_indexes` and every pool mutation run accrual before applying the requested operation, the affected `(hub_id, asset)` market becomes permanently unable to repay, withdraw, liquidate, clean bad debt, or otherwise mutate. [1](#0-0) [2](#0-1) 

### Finding Description

Each accrual step converts the market's scaled `borrowed` and `supplied` totals back to original RAY values through `scaled_to_original`, which is an unchecked-domain `Ray::mul` that panics on `i128` overflow. [3](#0-2) [2](#0-1) 

The borrow index is capped only after `borrow_index * interest_factor`; it does not prevent the separate market-total value `scaled_shares * index` from exceeding `i128::MAX` first. [4](#0-3) [3](#0-2) 

`global_sync` performs this calculation for every elapsed accrual chunk before market mutations, so once either market-total conversion crosses the representable range, every later operation on that market reverts at the same first accrual step. [5](#0-4) [6](#0-5) 

### Impact Explanation

This permanently freezes all funds represented by the affected market book: suppliers cannot withdraw, borrowers cannot repay, liquidators cannot seize, and cleanup or recapitalization paths that load and accrue the market cannot execute. [7](#0-6) [8](#0-7) 

The panic happens before the configured `MAX_BORROW_INDEX_RAY` cap is reached, so the intended terminal accrual bound does not provide a safe end state. [9](#0-8) 

### Likelihood Explanation

The trigger is permissionless: once sufficient time has elapsed, any unprivileged caller can invoke `Controller::update_indexes` with a vector containing the affected `HubAssetKey`, causing the pool accrual path to overflow. [1](#0-0) [10](#0-9) 

The precondition is narrow because the market must hold enough scaled shares for `shares * index` to exceed `i128::MAX`; the regression fixture uses one billion 18-decimal whole tokens supplied and approximately 98% borrowed under a steep 175% maximum-rate curve. [11](#0-10) 

Although the preconditions are extreme, admitted caps and bounded indexes do not make future accrued market values representable, and the test demonstrates the cliff in production-shaped controller and pool calls. [12](#0-11) [13](#0-12) 

### Recommendation

Make accrual overflow-safe before computing utilization: derive a per-market effective index bound from `i128::MAX / max(supplied, borrowed)` and clamp index growth to that bound, or use a checked/saturating market-value representation that cannot panic inside `scaled_to_original`. [3](#0-2) [2](#0-1) 

The bound must be applied inside `accrue_step`, not only to `update_borrow_index`, because the panic occurs while converting current totals before the new index is calculated. [3](#0-2) [4](#0-3) 

### Proof of Concept

The checked-in regression test constructs the vulnerable state and shows the freeze:

1. Create an 18-decimal market with the steep `xlm_curve` and a collateral market.
2. Supply `1_000_000_000 * 10^18` base units to the target market.
3. Borrow `98%` of that supply against sufficient collateral.
4. Advance ledger time in yearly intervals.
5. Call the permissionless controller `update_indexes` path for `HubAssetKey { hub_id, asset }`.
6. Once the index is large enough that `borrowed * borrow_index` exceeds `i128::MAX`, accrual returns `MathOverflow`.
7. Subsequent `withdraw` and `repay` calls also return `MathOverflow` because they accrue before mutating. [14](#0-13) 

The failing sequence is implemented by `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap`. [15](#0-14)

### Citations

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

**File:** common/src/rates/scaling.rs (L12-16)
```rust
/// Converts a scaled `Ray` amount to its original (unscaled) value by
/// multiplying by `index`, rounding half up.
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

**File:** common/src/rates/simulate.rs (L157-174)
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

**File:** contracts/pool/README.md (L161-167)
```markdown
```text
entrypoint (#[only_owner])
  → Cache::load             # read params + state, bump TTL
  → interest::global_sync   # accrue to now, in ≤1yr chunks
  → mutate                  # cache/shares.rs, cache/cash.rs
  → guards::*               # reserve, utilization, backing checks
  → commit → transfer_out → emit
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

**File:** docs/reference/formulas.md (L432-437)
```markdown
The token-to-RAY maximum is also the admitted cap maximum. Accrued position
values and market totals must independently fit the RAY domain; valid caps and
bounded indexes do not guarantee that future accrual fits. Value overflow can
occur before the index ceiling and block repayment/withdrawal because those
operations accrue first. At the borrow-index ceiling, further accrual produces
no borrower interest. No dedicated ceiling alarm is emitted.
```
