### Title
Debt-value `i128` overflow inside accrual permanently freezes a market — ([File: common/src/rates/index.rs])

### Summary
The MySQL CVE-2017-3641 class is an easily repeatable crash/DoS. The analog here is a permanent, unrecoverable panic in the pool's interest accrual: once `borrowed_shares * borrow_index` exceeds `i128` capacity, `accrue_step` panics with `MathOverflow`, and because every market verb accrues first, the market freezes forever — no repay, withdraw, liquidation, or bad-debt cleanup can ever execute again.

### Finding Description
`accrue_step` in `common/src/rates/simulate.rs` computes `borrowed_original = scaled_to_original(env, borrowed, borrow_index)` before doing anything else [1](#0-0) . `scaled_to_original` is a plain `scaled.mul(env, index)` that panics with `GenericError::MathOverflow` when the product does not fit `i128` [2](#0-1) . The same non-saturating multiply is used again in `calculate_supplier_rewards` for `new_total_debt` [3](#0-2) .

The borrow index is capped at `MAX_BORROW_INDEX_RAY` (10^36 raw RAY) only *after* the value multiply — the cap in `update_borrow_index` cannot prevent the overflow because the overflowing term is `borrowed * index`, not the index itself [4](#0-3) . The invariants doc acknowledges this gap: "Debt-value overflow can still revert accrual before that ceiling is reached" [5](#0-4) .

Every state-mutating pool entrypoint runs `interest::global_sync`, which calls `accrue_chunk` → `accrue_step` before the requested mutation [6](#0-5) . Once `borrowed * borrow_index` exceeds the representable range, the panic is permanent: interest only grows the index, `borrowed` shares cannot be burned because `repay`/`liquidate`/`clean_bad_debt`/`net_settle` all accrue first, and `update_indexes` — permissionless — hits the same trap [7](#0-6) .

The test `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` demonstrates it end-to-end: after the index grows ~170x on an 18-decimal book, `try_update_indexes_for`, `try_withdraw_raw`, and `try_repay` all return `MATH_OVERFLOW`, and the comment notes the market is frozen — "no repay, no withdraw, no liquidation" [7](#0-6) .

### Impact Explanation
Permanent freezing of funds for the affected `(hub, token)` market: every supplier's deposit, every borrower's collateral-backed position, and pending protocol revenue become unreachable. Liquidations cannot run, so a deteriorating book cannot be resolved and the freeze can convert into protocol insolvency. This is not fail-closed oracle behavior or a documented-parameter choice — it is an unconditional arithmetic trap on the mandatory accrual path, and the codebase's own test and invariants doc treat it as a real cliff rather than an accepted bound.

### Likelihood Explanation
Reaching the cliff requires a very large book (the test uses ~10^27 units of an 18-decimal asset) or sustained high-rate compounding. An unprivileged attacker cannot advance time, but can inflate `borrowed` scaled shares directly via `supply` + `borrow` up to the market cap, and the overflow threshold moves lower as the index grows — each year of accrual lowers the principal needed to trip it. Any subsequent permissionless `update_indexes` call detonates the freeze. Whale-capital requirement and time dependence keep this at Medium rather than High.

### Recommendation
In `accrue_step`, clamp debt value to a saturating bound (or detect `scaled_to_original` overflow) before computing utilization and rewards, so accrual degrades gracefully — e.g., stop growing the index once the debt value is at capacity and let `repay`/`liquidate`/`seize_positions` still execute against the saturated value. Alternatively, gate the freeze: let `repay`, `withdraw`, and seizure paths skip or bound accrual when the step would overflow, so funds remain exitable even if interest accounting stalls.

### Proof of Concept
Reproduced by the existing harness test at `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:321-360`:

1. Create an 18-decimal market with the XLM rate curve and lifted caps.
2. `supply(BOB, BIG18, 1e9 * 10^18)`; `supply(ALICE, COL, ...)`; `borrow(ALICE, BIG18, ~98% utilization)`.
3. Advance ledger time ~5+ years (achieved naturally on mainnet; attacker only needs to get the book large, time does the rest).
4. Any call — `update_indexes` (permissionless), `withdraw`, `repay` — panics `MathOverflow` inside `accrue_step → scaled_to_original(borrowed, borrow_index)`, before `borrow_index` ever reaches `MAX_BORROW_INDEX_RAY`. The panic is permanent since nothing can reduce `borrowed` without first accruing.

### Citations

**File:** common/src/rates/simulate.rs (L60-62)
```rust
    let borrowed_original = scaled_to_original(env, borrowed, borrow_index);
    let supplied_original = scaled_to_original(env, supplied, supply_index);
    let util = utilization(env, borrowed_original, supplied_original);
```

**File:** common/src/rates/scaling.rs (L14-16)
```rust
pub fn scaled_to_original(env: &Env, scaled: Ray, index: Ray) -> Ray {
    scaled.mul(env, index)
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

**File:** common/src/rates/index.rs (L80-83)
```rust
    let old_total_debt = borrowed.mul(env, old_borrow_index);
    let new_total_debt = borrowed.mul(env, new_borrow_index);

    let accrued_interest = new_total_debt.checked_sub(env, old_total_debt);
```

**File:** docs/reference/invariants.md (L235-236)
```markdown
Debt-value overflow can still revert accrual before that ceiling is reached.
Bounded indexes do not guarantee representable position or market values.
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
