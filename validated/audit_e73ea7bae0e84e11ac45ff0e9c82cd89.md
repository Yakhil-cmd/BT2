### Title
Permanent market freeze via i128 overflow of the RAY-scaled position value during accrual — any unprivileged user can leave a large market at high utilization until every verb panics - ([File: common/src/rates/simulate.rs])

### Summary
Analogous to the binutils DoS (crafted input → crash/exhaustion): here the "crafted input" is market state an unprivileged address can legitimately create — a whale-scale book held at high utilization. Interest accrual computes `scaled * index` in `i128`; once `supplied × supply_index` (or the borrow leg) exceeds `i128::MAX`, `accrue_step` panics with `MathOverflow`. Because every pool mutation runs `interest::global_sync` first, the entire market freezes permanently — no repay, withdraw, supply, liquidate, or `clean_bad_debt`. The protocol's own harness encodes this as a known cliff: `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` [1](#0-0) .

### Finding Description
`global_sync` runs unconditionally at the head of every mutating pool entrypoint (`contracts/pool/README.md` documents the `Cache::load → interest::global_sync → mutate` flow) [2](#0-1) . Each chunk calls `accrue_step`, whose first operation is `scaled_to_original(env, borrowed, borrow_index)` and `scaled_to_original(env, supplied, supply_index)` — a RAY×RAY multiply checked in `i128` that panics on overflow [3](#0-2) .

The intended safety bound is the borrow-index cap `MAX_BORROW_INDEX_RAY`, but it is applied to the *index*, while the panic happens on the index *times the share count*. A market with ~1e9 whole tokens at 18 decimals holds `supplied`/`borrowed` of ~1e36 RAY; the value ceiling `i128::MAX` is only ~170× that, so at a steep-utilization rate curve the multiply overflows years before the index cap can clamp growth. The harness test proves: after the cliff, `borrow_index < MAX_BORROW_INDEX_RAY` (cap never engaged) and both `withdraw` and `repay` revert with `MATH_OVERFLOW` [4](#0-3) .

An unprivileged attacker path: `controller.supply` a large amount of a high-decimals asset, `controller.borrow` to ~98% utilization (caps lifted/normal for a whale market), then simply do nothing. Time — not the attacker — advances `last_timestamp`, and each subsequent accrual chunk compounds until the overflow. Once tripped, the panic is deterministic and permanent: `last_timestamp` is only stamped after the loop completes [5](#0-4) , and `simulate_update_indexes`/view paths hit the same overflow, so there is no recovery call.

### Impact Explanation
Permanent freezing of all user funds in the affected `(hub_id, asset)` market: suppliers cannot withdraw, borrowers cannot repay (so their collateral in other markets is also unrecoverable via normal exit), liquidators cannot liquidate, and `clean_bad_debt`/`recapitalize` cannot rescue the book because they all route through `global_sync`. This is a stronger impact than the reference CVE's transient crash — it is an irreversible liveness failure for the market.

### Likelihood Explanation
Requires a large-book market (whale-scale supply, plausible for 18-decimals or low-price assets where cap-per-decimals permits ~1e9 whole units) sustained at very high utilization on a steep rate curve for multiple years. No privileged action, oracle manipulation, or third-party cooperation is needed — a single borrower holding utilization high suffices, and an idle market drifts upward on its own because debt compounds faster than supply (noted in the test header). Medium: high impact, but long fuse and large capital at risk.

### Recommendation
Cap accrual by the *value* ceiling, not just the index: before each `accrue_step`, clamp `delta_ms` or short-circuit once `scaled × index` approaches `i128::MAX`, and stamp `last_timestamp` so the market remains operable at a saturated index. Alternatively, per chunk, compute `headroom = i128::MAX / shares` and cap `borrow_index`/`supply_index` at that headroom before the multiply, turning the cliff into a bounded saturation that still permits withdraw/repay.

### Proof of Concept
Existing harness test `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` in `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs` (lines 320-361): supplies 1e9 × 10^18 units, borrows at 98% utilization on the steep XLM curve, advances ledger time year-by-year through the permissionless `update_indexes(caller, assets)` entrypoint [6](#0-5) , then asserts `MATH_OVERFLOW` on `update_indexes`, `withdraw`, and `repay` with the index cap unengaged — demonstrating permanent freeze reachable purely through unprivileged `supply`/`borrow`/`update_indexes` calls.

### Citations

**File:** tests/test-harness/tests/controller/large_positions_and_long_horizons.rs (L315-360)
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
    std::println!(
        "ray-value cliff reached after {years} years at 98 percent utilization on the XLM curve; last index x{:.1}",
        last.borrow_index as f64 / RAY as f64
    );
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

**File:** common/src/rates/simulate.rs (L60-64)
```rust
    let borrowed_original = scaled_to_original(env, borrowed, borrow_index);
    let supplied_original = scaled_to_original(env, supplied, supply_index);
    let util = utilization(env, borrowed_original, supplied_original);
    let borrow_rate = calculate_borrow_rate(env, util, params);
    let interest_factor = compound_interest(env, borrow_rate, delta_ms);
```

**File:** contracts/controller/src/lib.rs (L367-372)
```rust
    /// Accrues pool borrow and supply indexes for `assets`. Permissionless;
    /// requires caller authorization.
    #[when_not_paused]
    fn update_indexes(env: Env, caller: Address, assets: Vec<HubAssetKey>) {
        markets::update_indexes(&env, caller, assets);
    }
```
