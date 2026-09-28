### Title
Unprivileged borrow at sustained high utilization permanently freezes a market via i128 overflow in Ray-scaled accrual - (File: common/src/rates/scaling.rs)

### Summary
The NATS advisory is a crash-on-malformed-message DoS. The analog in XOXNO Lending is a crash-on-accrual DoS: every mutating pool verb runs `global_sync` first, and accrual multiplies scaled Ray balances by the growing indexes with a panicking (non-saturating) multiply. A single unprivileged address can put a market into the state — very large scaled debt at sustained high utilization — where `scaled * index` exceeds `i128::MAX`. Once crossed, the accrual panic is permanent: the borrow-index cap `MAX_BORROW_INDEX_RAY` is checked on the index, not on the product, so it never engages before the value overflow bricks the market. [1](#0-0) [2](#0-1) 

### Finding Description
`interest::global_sync` runs at the head of every pool mutation (`Cache::load` → `global_sync` → mutate → commit, per the pool flow), and calls `accrue_step` for each elapsed chunk. The accrual computes `borrowed.mul(borrow_index)` and `supplied.mul(supply_index)` — `calculate_supplier_rewards` at `common/src/rates/index.rs:80-81` multiplies `borrowed` by both indexes, and `update_supply_index` at `common/src/rates/index.rs:34` multiplies `supplied` by the old index. These resolve through `scaled_to_original`/`Ray::mul` (`common/src/rates/scaling.rs:14-16`), which panics on `i128` overflow rather than saturating. [3](#0-2) [4](#0-3) 

The only ceiling, `MAX_BORROW_INDEX_RAY`, bounds the index value itself (`old_index.mul(interest_factor)`), not the debt value. With a large enough scaled position, `scaled * index` overflows `i128::MAX` while the index is still far below its cap — the checked panic fires first and no code path clamps the product. The in-repo test `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` demonstrates exactly this: an 18-decimal market with ~1e9-token principal at ~98% utilization overflows in a few years, after which `withdraw`, `repay`, and `update_indexes` all revert with `MathOverflow` forever — "no repay, no withdraw, no liquidation." [5](#0-4) 

Attacker reachability: `supply` and `borrow` are unprivileged controller entrypoints. A single address supplies a large amount of a high-decimal asset, borrows to the utilization ceiling, and lets accrual compound on the steep (post-optimal) rate segment. Any subsequent touch of the market — the attacker's own `update_indexes` call, or anyone's `supply`/`borrow`/`repay`/`withdraw`/`liquidate`/`recapitalize`/`flash_loan` — triggers the panic. Once `scaled * index > i128::MAX`, no ordering of calls avoids it because accrual precedes every mutator and the index only grows.

### Impact Explanation
Permanent freezing of all user funds in the affected market: every exit path (`withdraw`, `repay`, `liquidate`, `clean_bad_debt` via `seize_positions`, `claim_revenue`, `recapitalize`) accrues first and panics. Suppliers can never withdraw, borrowers can never repay, liquidators cannot clear bad debt, and protocol revenue is unclaimable. Because the same token may be listed in multiple hubs over one physical pool balance, the stranded tokens are also unavailable to the sibling markets' cash. This is the lending analog of the NATS pre-auth crash: an unprivileged trigger produces a condition under which the server can never process the affected input again — here, the market can never process any operation again. [6](#0-5) [7](#0-6) 

### Likelihood Explanation
Severity Medium/High, likelihood bounded by capital and configuration. The attack requires: (a) a listed high-decimal asset (decimals up to 18 are admitted), (b) enough real token capital to put the scaled book near the Ray-value domain ceiling (~1e9 whole tokens at 18 decimals), and (c) sustained high utilization — the demonstrated case needs `max_utilization` permissive enough to reach the steep curve segment and years of compounding, so it is slow rather than instantaneous. It is not a documented ADR choice — the test explicitly flags that the documented bound in `docs/reference/formulas.md` is wrong and that the index cap "did not engage before the value overflow." One uncertainty I could not fully resolve within the indexed code: whether any production `max_utilization`/`supply cap` configuration keeps the required scaled-debt magnitude strictly unreachable; INV-HALT-03 shows caps can fail open when the supply index drops below RAY after bad-debt write-downs, which lowers the barrier. [8](#0-7) [9](#0-8) 

### Recommendation
Make accrual fail-safe instead of panicking:
- In `update_borrow_index` / `accrue_step`, clamp the index or the resulting debt value so that `borrowed.mul(new_borrow_index)` stays within `i128::MAX` — e.g., cap `new_borrow_index` at `min(MAX_BORROW_INDEX_RAY, i128::MAX / borrowed.raw() * RAY)` when `borrowed > 0`, before computing `new_total_debt`.
- Apply the same saturation to `supplied.mul(supply_index)` in `update_supply_index` (`common/src/rates/index.rs:34`) — use `mul_div_floor_saturating`-style semantics or pre-check headroom, consistent with `protocol_fee_shares` which already clamps to `i128::MAX` headroom at `common/src/rates/index.rs:94-99`. [10](#0-9) 
- Enforce a hard per-market scaled-supply/borrow cap in the pool itself (not only the saturating controller-side cap conversion of INV-HALT-03), so a book cannot be grown to the Ray-value ceiling regardless of index state.
- Add a regression test asserting that at the largest admitted scaled position, accrual over arbitrarily long horizons clamps rather than panics, and that `withdraw`/`repay` remain callable.

### Proof of Concept
The codebase already contains the demonstrating test at `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:320-361`. Sketch of the attacker path:

```rust
// 1. List an 18-decimal asset with the steep (XLM-style) rate curve.
let mut t = LendingTest::new()
    .with_market(big("BIG18", 18, xlm_curve()))
    .with_market(col())
    .with_max_utilization_disabled_all_markets()
    .build();
lift_caps(&t, "BIG18", 18);          // caps at max_cap_for_decimals

// 2. Unprivileged: supply ~1e9 whole tokens, borrow ~98% utilization.
let principal = BILLION * 10i128.pow(18);
t.supply_raw(BOB, "BIG18", principal);
t.supply_raw(ALICE, "COL", BILLION * 10_000_000 * 3);
t.borrow_raw(ALICE, "BIG18", principal / 100 * 98);

// 3. Accrue on the steep curve until scaled * index > i128::MAX.
loop {
    t.advance_time(YEAR_SECS);
    if t.try_update_indexes_for(&["BIG18"]).is_err() { break; }
}
// → Error(Contract, MathOverflow); borrow_index still < MAX_BORROW_INDEX_RAY

// 4. Permanent freeze: every verb accrues first and hits the same panic.
assert_contract_error(t.try_withdraw_raw(BOB, "BIG18", 1), errors::MATH_OVERFLOW);
assert_contract_error(t.try_repay(ALICE, "BIG18", 1.0), errors::MATH_OVERFLOW);
// liquidate, clean_bad_debt, claim_revenue, recapitalize fail identically
```

On-chain, the attacker substitutes repeated `update_indexes`/`supply`/`borrow` calls over real ledger time for `advance_time`; the terminal state and revert set are identical because `global_sync` precedes every mutating entrypoint.

### Citations

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

**File:** common/src/rates/index.rs (L79-88)
```rust
) -> (Ray, Ray) {
    let old_total_debt = borrowed.mul(env, old_borrow_index);
    let new_total_debt = borrowed.mul(env, new_borrow_index);

    let accrued_interest = new_total_debt.checked_sub(env, old_total_debt);

    let protocol_fee = params.reserve_factor.apply_to_ray(env, accrued_interest);
    let supplier_rewards = accrued_interest.checked_sub(env, protocol_fee);

    (supplier_rewards, protocol_fee)
```

**File:** common/src/rates/index.rs (L91-99)
```rust
/// Converts a Ray-denominated `fee` into scaled supply-index shares
/// (`fee / supply_index`), floor-rounded and saturating on overflow. Caps the
/// result so that adding it to `supplied` cannot overflow `i128::MAX`.
pub fn protocol_fee_shares(env: &Env, fee: Ray, supply_index: Ray, supplied: Ray) -> Ray {
    let raw = fp_core::mul_div_floor_saturating(env, fee.raw(), RAY, supply_index.raw());

    let headroom = i128::MAX.saturating_sub(supplied.raw());
    Ray::from(raw.min(headroom))
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

**File:** docs/reference/architecture.md (L61-66)
```markdown
arbitrary token is safe.

The same token can appear in multiple hubs. Its markets keep separate books
but share one physical pool balance. A malicious token contract can therefore
affect more than one market. See [token assumptions](../explanation/threat-model.md#token-assumptions).

```

**File:** docs/reference/invariants.md (L506-524)
```markdown
<a id="inv-halt-03"></a>

### INV-HALT-03 — Cap entry checks; scaled conversion can fail open

A zero supply or borrow cap admits no positive entry. Entry compares scaled
usage against the asset-unit cap converted at the returned live index.

That conversion saturates at `i128::MAX` instead of reverting, so the scaled
cap can fail open: once saturated, the configured asset-unit limit is not
enforced. An admitted cap saturates only at an index below one RAY. At the
supply-index floor (`RAY / 1000`), a supply cap above 1/1000 of the admitted
maximum saturates. The borrow index never falls below one RAY, so an admitted
borrow cap cannot saturate. See
[cap conversion](formulas.md#caps-fees-and-numeric-limits).

Exits consume no cap. Missing usage rows and zero deltas are no-ops, and stored
usage cannot become negative. Same-spoke liquidation credit bypasses entry
caps and books its fee as an exit.

```
