### Title
Unrecoverable `MathOverflow` panic in interest accrual permanently freezes an entire market's funds - ([File: contracts/pool/src/interest.rs](contracts/pool/src/interest.rs))

### Summary
`global_sync` runs before every market mutation (`supply`, `borrow`, `withdraw`, `repay`, `seize_positions`/liquidation, `net_settle`, `flash_loan`, `recapitalize`, `claim_revenue`) and on the permissionless `update_indexes`. Inside `accrue_step`, the debt-value computation `half_up(borrowed * borrow_index / RAY)` widens through checked arithmetic; once `borrowed * borrow_index` exceeds the representable domain, the step panics with `MathOverflow`. The borrow-index ceiling (`MAX_BORROW_INDEX_RAY = 10^36`) does not protect this: the value multiplication overflows before the index reaches its cap, so the market can never accrue again and every verb that accrues first reverts forever. This is the same bug class as CVE-2020-23308: a reachable internal assertion/panic on a path that cannot be recovered, turning a state-dependent overflow into a permanent denial of service on user funds.

### Finding Description
`contracts/pool/src/interest.rs::global_sync` iterates `accrue_chunk` over `MAX_COMPOUND_DELTA_MS` windows and writes the resulting indexes back into the cache (`accrue_chunk` sets `borrow_index` and `supply_index` and mints `revenue_shares`). Per `skills/xoxno-lending/math.md` and `docs/reference/formulas.md`, each step computes `interest = half_up(borrowed × borrow_index' / RAY) − half_up(borrowed × borrow_index / RAY)`. With `borrowed` being a RAY-scaled share quantity and `borrow_index` a RAY index, the product is on the order of `borrowed_raw × index_raw`; for whale-scale markets (e.g., 10^9 tokens at 18 decimals ⇒ ~10^36 RAY-scaled borrowed) multiplied by an index growing several× under sustained max-curve utilization, the intermediate product overflows `i128`/`I256` before `update_borrow_index`'s `min(..., 10^36)` cap is reached.

The repo's own harness proves this is reachable and unrecoverable: `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs::a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` supplies ~1e9·10^18 units, borrows 98%, advances time year by year through the permissionless `update_indexes`, and observes `MathOverflow` at `borrow_index < MAX_BORROW_INDEX_RAY` — after which `withdraw` and `repay` also revert with `MathOverflow` because they accrue first. `docs/reference/invariants.md` (INV-IDX-01) explicitly concedes: "Debt-value overflow can still revert accrual before that ceiling is reached." The in-scope entrypoints affected: `update_indexes` (permissionless trigger and freeze), then `withdraw`, `repay`, `supply`, `borrow`, `seize_positions` (liquidation), `net_settle`, `flash_loan`, `claim_revenue`, `recapitalize` — all gated behind `Cache::load` → `global_sync`.

### Impact Explanation
Permanent freezing of all user funds in the affected `(hub, asset)` market. Once the accrual panic state is entered, no path exists to unwind it: `repay` cannot reduce `borrowed` (it accrues first), `withdraw`/`claim_revenue` cannot release supply or treasury revenue, liquidations cannot close bad positions, and `recapitalize` cannot inject backing. Suppliers lose their entire deposited principal in that market, borrowers cannot recover collateral gated on repayment elsewhere, and unclaimed protocol revenue is frozen. Unlike an oracle fail-closed (rejected by the rules), this is an unrecoverable arithmetic panic embedded in state — there is no external condition to wait out.

### Likelihood Explanation
Reaching the cliff requires a large market (on the order of billions of whole tokens in scaled terms) at sustained ~maximum-utilization on a steep rate segment for multiple years — the harness shows the panic lands within ~40 years at 98% utilization, sooner at higher index multipliers. An unprivileged attacker cannot force other users' capital, but any user can hold a leveraged borrow position at high utilization, and calling `update_indexes` to compound is permissionless — each call ratchets `borrow_index` and `last_timestamp` forward, and a keeper or user calling it steadily will walk the market onto the cliff whether or not utilization stays high later (the index is monotone). It is not cheap or fast, but it needs no privilege, no oracle manipulation, and no cooperation from anyone else. Rated Medium: the impact is critical (permanent freeze of all market funds) but the trigger demands extreme scale and sustained utilization.

### Recommendation
Cap the *value* computation, not just the index. Concretely: in `accrue_step` (common/src/rates), perform `borrowed × borrow_index` via the widening `I256` path and saturate/truncate interest rather than panicking; alternatively, clamp `borrow_index` earlier so that `borrowed × index ≤ i128::MAX` for the protocol's maximum representable `borrowed` (i.e., derive the effective index cap from `i128::MAX / borrowed` at accrual time instead of the fixed `MAX_BORROW_INDEX_RAY`). At minimum, when the product would overflow, stop advancing `borrow_index` for the remainder of the call but still set `last_timestamp`, so other verbs continue to work with a frozen index rather than the whole market being bricked.

### Proof of Concept
Existing in-repo demonstration: `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs` (~lines 320–360), test `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap`:

```rust
let principal = BILLION * 10i128.pow(18);
t.supply_raw(BOB, "BIG18", principal);
let debt = principal / 100 * 98;
t.borrow_raw(ALICE, "BIG18", debt);

// advance one year at a time, calling the permissionless update_indexes
loop {
    t.advance_time(YEAR_SECS);
    if let Err(e) = t.try_update_indexes_for(&["BIG18"]) { break e; }
}
// asserts: contract error == MATH_OVERFLOW, borrow_index < MAX_BORROW_INDEX_RAY
assert_contract_error(t.try_withdraw_raw(BOB, "BIG18", 1), errors::MATH_OVERFLOW);
assert_contract_error(t.try_repay(ALICE, "BIG18", 1.0), errors::MATH_OVERFLOW);
```

Sequence an unprivileged user can submit on a real market:
1. `supply(hub, asset, amount)` and `borrow(...)` (or `multiply`) to push utilization near the curve's max-slope region at whale scale.
2. Repeatedly call `update_indexes(hub_asset)` as time passes — permissionless; each call advances `borrow_index`.
3. Once `borrowed_scaled × borrow_index` overflows inside `accrue_step`, the call returns `MathOverflow` and `last_timestamp` is never updated past the cliff.
4. Every subsequent `withdraw`, `repay`, `liquidate` (`seize_positions`), `flash_loan`, `claim_revenue`, and `recapitalize` on that market reverts with `MathOverflow` — permanently.

Caveat: this rests on the harness test's own assertion that the freeze is real and unrecoverable; I could not trace every guard in `accrue_step` to rule out an intervening utilization clamp that prevents the exact overflow point in all parameterizations, but the checked-arithmetic panic in accrual and the demonstrated end-state (repay/withdraw/liquidate all bricked) are directly evidenced in the repo. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

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

**File:** docs/reference/invariants.md (L229-237)
```markdown
### INV-IDX-01 — Borrow index is monotone and bounded

Both indexes start at one RAY. Successful accrual with validated rate parameters
cannot lower the borrow index and caps it at the protocol constant 10^36 raw
RAY. At the ceiling, further accrual produces no borrower interest.

Debt-value overflow can still revert accrual before that ceiling is reached.
Bounded indexes do not guarantee representable position or market values.

```

**File:** skills/xoxno-lending/math.md (L225-247)
```markdown
## Index accrual

`common/src/rates/simulate.rs::accrue_step` runs on every mutation (`contracts/pool/src/interest.rs`) and in the projection views (`get_bulk_indexes`, controller `get_market_index`, `get_market_indexes_detailed`, and every controller account view, which fetch simulated indexes through `Context::cached_market_index`).

Per step of `delta_ms ≤ MILLISECONDS_PER_YEAR` (`MAX_COMPOUND_DELTA_MS`; longer gaps are chunked, each chunk recomputing utilization with the revenue shares minted by the previous chunk):

```text
per_ms     = half_up(annual_borrow_rate_ray / 31_556_926_000)          // calculate_borrow_rate
x          = per_ms × delta_ms                                           // RAY exponent, must fit i128
factor     = 1 + x + x²/2! + … + x⁸/8!   (each power half-up, each term half-up ÷ k!)   // eighth-order approximation
borrow_index' = min(half_up(borrow_index × factor / RAY), 10^36)         // update_borrow_index, monotone
interest   = half_up(borrowed × borrow_index' / RAY) − half_up(borrowed × borrow_index / RAY)
fee        = half_up(interest × reserve_factor / BPS);  rewards = interest − fee
supply_index' = clamp(floor((half_up(supplied × supply_index / RAY) + rewards) × RAY / supplied), supply_index, 10^36)
shortfall  = rewards − (half_up(supplied × supply_index' / RAY) − half_up(supplied × supply_index / RAY))   // booked to protocol
revenue_shares = min(floor((fee + shortfall) × RAY / supply_index'), i128::MAX − supplied)   // added to supplied and revenue
```

Monotonicity:

- Borrow index only grows (capped at `MAX_BORROW_INDEX_RAY`; at the cap no further interest accrues).
- Supply index never decreases from accrual, but **bad-debt socialization lowers it** (see below), floored at `SUPPLY_INDEX_FLOOR_RAW = 10^24`. A supply index below an earlier reading means a bad-debt write-down on that market, not an accrual bug.
- Revenue shares are part of `supplied`; the supply index applies to them like any supplier.
```
