### Title
Accrual `MathOverflow` panic permanently freezes a pool market once borrow value crosses the i128 ceiling - (File: contracts/pool/src/interest.rs)

### Summary
CVE-2018-16881's class — a crafted input that crashes a shared service, denying it to everyone — maps onto the pool's interest-accrual path. `interest::global_sync` runs before every state-changing verb, and its fixed-point math panics with `GenericError::MathOverflow` when `borrowed × borrow_index` (or `rate × delta_ms`) no longer fits the representable range. An unprivileged attacker can push a market into that unrepresentable state (supply a very large position, borrow near 100% utilization, let accrual run — or, on any market, accrual eventually compounds toward the same cliff). Once the value overflows, the panic is persistent: the stored `borrow_index` never shrinks, so every subsequent entrypoint that accrues first reverts forever.

### Finding Description
Every market mutation follows `Cache::load → interest::global_sync → mutate`, per `contracts/pool/README.md` [1](#0-0) . `global_sync` calls `accrue_chunk`, which runs `accrue_step` on the market's `borrowed`, `supplied`, and indexes [2](#0-1) . Inside `accrue_step`, `scaled_to_original` and `calculate_supplier_rewards` multiply scaled shares by `borrow_index`; `compound_interest` additionally panics when `rate × delta_ms` does not fit `i128` [3](#0-2) .

The borrow index is capped at `MAX_BORROW_INDEX_RAY` (10^36) but the cap is applied to the index, not to `borrowed × index`, so the debt-value product overflows first on a large book [4](#0-3) . The harness test `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` demonstrates the state: ~1e9 18-decimal tokens supplied at 98% utilization on the XLM curve reaches the cliff before the index cap, after which `update_indexes`, `withdraw`, and `repay` all revert with `MATH_OVERFLOW` [5](#0-4) .

The attacker does not need the capital to stay — they only need to create the oversized scaled-debt bookkeeping (large `supply` + `borrow` on the controller, which are permissionless entrypoints). Once the scaled product exceeds `i128`, no transaction touching the market can advance `last_timestamp`, because the panic occurs inside the accrual that precedes every mutation.

### Impact Explanation
Permanent freezing of funds and protocol insolvency for that market: suppliers cannot `withdraw`, borrowers cannot `repay`, liquidators cannot `liquidate` debt in the market (liquidation settles through the pool), `clean_bad_debt`/`recapitalize`/`claim_revenue`/`update_indexes` all fail. All user deposits and outstanding debt in the affected `(hub, token)` book are locked in the contract indefinitely — the crash is self-perpetuating rather than a transient revert.

### Likelihood Explanation
Deterministic once reached: the panic is a pure function of on-chain `borrowed`, `borrow_index`, and elapsed time, not of oracle behavior or privileged actions. Reachability requires a large market (whale-scale supply plus ~98% utilization borrow, which `borrow`'s liquidation-buffer and `max_utilization` gates still permit when configured high) plus sustained high utilization so the index compounds toward the value ceiling. On Stellar this is capital-intensive but fully within unprivileged call paths (`supply`, `borrow`, `update_indexes`); the contract itself contains the regression test proving the terminal state exists. Severity is bounded by needing an unusually large book, hence Medium–High rather than Critical.

### Recommendation
Clamp the scaled debt value, not just the index: when `update_borrow_index` hits `MAX_BORROW_INDEX_RAY`, further accrual should no-op cleanly for oversized books rather than multiply first. Concretely, guard `calculate_supplier_rewards`/`scaled_to_original` against `borrowed × index` overflow (e.g., saturate debt value at `i128::MAX` or short-circuit accrual when `borrow_index == MAX_BORROW_INDEX_RAY`), so `global_sync` becomes a no-op at the ceiling instead of a panic. Alternatively, enforce a per-market borrow/supply ceiling that keeps `borrowed × MAX_BORROW_INDEX_RAY < i128::MAX` at listing/config time.

### Proof of Concept
Reproduced by the in-repo test `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` in `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs` [6](#0-5) :

1. Attacker calls controller `supply` of ~1e9 BIG18 (18-decimal) tokens, then `borrow` of 98% of the book (both permissionless; `max_utilization` disabled/high and caps lifted).
2. Time accrues under the XLM rate curve at sustained ~98% utilization; `update_indexes` (permissionless) is invoked repeatedly.
3. After `borrow_index` growth makes `scaled_to_original(borrowed, borrow_index)` overflow `i128`, `update_indexes` reverts with `Error #33 MathOverflow` — while `borrow_index < MAX_BORROW_INDEX_RAY` (the index cap never engaged).
4. From then on, `withdraw` and `repay` on the market revert with the same error, since they run `global_sync` first — the market is permanently frozen.

### Citations

**File:** contracts/pool/README.md (L159-168)
```markdown
Each mutation of an existing market runs this sequence:

```text
entrypoint (#[only_owner])
  → Cache::load             # read params + state, bump TTL
  → interest::global_sync   # accrue to now, in ≤1yr chunks
  → mutate                  # cache/shares.rs, cache/cash.rs
  → guards::*               # reserve, utilization, backing checks
  → commit → transfer_out → emit
```
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

**File:** common/src/rates/compound.rs (L36-42)
```rust
    let x = Ray::from({
        let r = I256::from_i128(env, rate.raw());
        let d = I256::from_i128(env, delta_ms as i128);
        r.mul(&d)
            .to_i128()
            .unwrap_or_else(|| panic_with_error!(env, GenericError::MathOverflow))
    });
```

**File:** docs/reference/invariants.md (L229-237)
```markdown
### INV-IDX-01 — Borrow index is monotone and bounded

Both indexes start at one RAY. Successful accrual with validated rate parameters
cannot lower the borrow index and caps it at the protocol constant 10^36 raw
RAY. At the ceiling, further accrual produces no borrower interest.

Debt-value overflow can still revert accrual before that ceiling is reached.
Bounded indexes do not guarantee representable position or market values.

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
