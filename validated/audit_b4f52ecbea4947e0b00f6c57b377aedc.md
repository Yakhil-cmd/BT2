### Title
Permanent market freeze via `i128` overflow in index accrual — (`contracts/pool/src/interest.rs`, `common/src/rates/simulate.rs`)

### Summary
The MySQL CVE is a reachable crash that yields a complete denial of service. The direct analog in XOXNO Lending is the RAY-value cliff in interest accrual: `accrue_step` multiplies total scaled debt `borrowed` by the growing `borrow_index` inside `scaled_to_original`, and panics with `GenericError::MathOverflow` once `borrowed * borrow_index` exceeds `i128::MAX`. Because `global_sync` runs accrual before every pool mutation and view, one overflow permanently bricks the market — no repay, no withdraw, no liquidation, no `update_indexes`. The repo's own harness test documents exactly this freeze. [1](#0-0) [2](#0-1) 

### Finding Description
`global_sync` in `contracts/pool/src/interest.rs` chunks elapsed time and calls `accrue_step` for each chunk [3](#0-2) . `accrue_step` computes `borrowed_original = scaled_to_original(env, borrowed, borrow_index)` and then `calculate_supplier_rewards(..., borrowed, new_borrow_index, borrow_index)`, which internally re-values `borrowed` at the new index [4](#0-3) . `scaled_to_original` is `scaled.mul(env, index)`, i.e. `shares * index / RAY`; when `borrowed * index` exceeds the representable range the fixed-point layer raises `MathOverflow` [5](#0-4) [6](#0-5) .

The borrow index is monotone and capped at `MAX_BORROW_INDEX_RAY` (10^36 raw, ~10^9 × RAY) [7](#0-6) , but the value ceiling `i128::MAX ≈ 1.7e38` is hit first whenever `borrowed` (RAY-scaled, so `tokens * 10^(27−d)`) is large. The test `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` shows a 10^9-whole-token, 18-decimals market at 98% utilization on the XLM curve hitting the cliff in a few years, asserts the index cap did not engage, and then asserts `try_withdraw_raw`, `try_repay`, and `try_update_indexes_for` all revert with `MATH_OVERFLOW` [8](#0-7) .

Since accrual runs at the head of every state-changing entrypoint (supply, borrow, withdraw, repay, liquidate, clean_bad_debt, flash paths all pass through the pool cache that calls `global_sync`), once `borrowed * borrow_index ≥ i128::MAX` every subsequent call on that market panics at the same arithmetic site. There is no recovery path: accrual cannot be skipped, the index cannot be rolled back, and bad-debt write-down also accrues first.

### Impact Explanation
Permanent freezing of funds. All suppliers' deposits in the affected market are unrecoverable (withdraw and claim_revenue panic), borrowers cannot repay or close, and liquidations cannot run, so positions can neither exit nor be liquidated. An attacker who holds the debt leg loses only the collateral they posted; every other supplier in the market loses their full deposit. This matches the accepted "permanent freezing of funds" impact and is the on-chain equivalent of the CVE's "complete DOS" outcome.

### Likelihood Explanation
A single unprivileged address can drive the market to the cliff using only in-scope entrypoints: `supply` a whale-scale amount of the market token and `borrow` it back to sustained high utilization against their own collateral, then let accrual time do the rest; alternately `update_indexes` is permissionless and can be called by anyone to advance accrual once the index is near the cliff. No privileged action, oracle manipulation, or leaked key is required. The cost is capital: the overflow needs `borrowed * index` to exceed ~1.7e38, i.e. roughly ≥10^11–10^12 raw token units at 7 decimals or ~10^9 whole tokens at 18 decimals, sustained at high utilization on a steep rate curve over multiple years. That is an expensive but entirely feasible griefing attack against any genuinely large market, and it also arises organically — the test shows honest usage at 98% utilization crosses the cliff before the index cap. Medium severity: devastating impact on the affected market, gated by whale capital and elapsed time.

### Recommendation
In `accrue_step` / `calculate_supplier_rewards` (`common/src/rates/simulate.rs`, `common/src/rates/index.rs`), handle the unrepresentable debt value gracefully instead of panicking: e.g. clamp `borrowed_original`/`new_debt` at the representable ceiling or saturate accrual when `borrowed` exceeds `i128::MAX / borrow_index`, so accrual becomes a bounded no-op rather than a permanent trap. Additionally, consider gating `supply`/`borrow` with a market-level cap on scaled totals derived from `i128::MAX / MAX_BORROW_INDEX_RAY` so the cliff is unreachable, and add a last-resort exit path (e.g. withdrawal that skips accrual) for markets that have already crossed it.

### Proof of Concept
Encoded in the repo's own test `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` (`tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:321-356`):

1. Attacker calls `supply` on market `BIG18` (18 decimals, XLM curve) with `principal = 10^9 * 10^18` base units.
2. Attacker supplies collateral token and calls `borrow` for `0.98 * principal` (98% utilization).
3. Time advances (or attacker/other users call `update_indexes`); at the steep segment of the curve `borrow_index` grows past ~170×.
4. Next `accrue_step` panics in `scaled_to_original(borrowed, borrow_index)` with `GenericError::MathOverflow`.
5. From then on: `update_indexes`, `repay` (even 1 unit), `withdraw` (even 1 unit), and `liquidate` all revert with `MATH_OVERFLOW` — asserted by the test. The market is permanently frozen while `borrow_index < MAX_BORROW_INDEX_RAY`.

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

**File:** contracts/pool/src/interest.rs (L20-53)
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

/// Applies one compound step of `delta_ms` to indexes and protocol revenue.
///
/// The arithmetic lives in [`accrue_step`], shared with the read-only
/// `simulate_update_indexes` so the view and the mutator cannot drift.
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

**File:** common/src/rates/scaling.rs (L12-16)
```rust
/// Converts a scaled `Ray` amount to its original (unscaled) value by
/// multiplying by `index`, rounding half up.
pub fn scaled_to_original(env: &Env, scaled: Ray, index: Ray) -> Ray {
    scaled.mul(env, index)
}
```

**File:** common/src/math/fp_core.rs (L1-10)
```rust
//! Raw `i128` arithmetic primitives behind the fixed-point newtypes in
//! [`super::fp`]: overflow-safe `x * y / d` with half-up, floor and ceiling
//! rounding, plus rescaling between decimal precisions.
//!
//! Every multiply-divide first attempts the whole computation in `i128` and
//! only widens the operands to `I256` when the intermediate product does not
//! fit. The widened path is exact, so both paths return the same value.
//! `I256` operations are host calls, so the `i128` path costs less.

use soroban_sdk::{panic_with_error, Env, I256};
```

**File:** docs/reference/invariants.md (L229-236)
```markdown
### INV-IDX-01 — Borrow index is monotone and bounded

Both indexes start at one RAY. Successful accrual with validated rate parameters
cannot lower the borrow index and caps it at the protocol constant 10^36 raw
RAY. At the ceiling, further accrual produces no borrower interest.

Debt-value overflow can still revert accrual before that ceiling is reached.
Bounded indexes do not guarantee representable position or market values.
```
