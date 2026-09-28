### Title
Whale-sized borrow book freezes a market permanently when `borrowed * borrow_index` overflows i128 before the index cap engages - (File: common/src/rates/scaling.rs)

### Summary
The TSEM incident class is a ransom-forced shutdown: operations halt and assets are locked. The on-chain analog is an irreversible accrual panic that permanently freezes every position in a (hub, asset) book. The pool's index bounds only cap `borrow_index` at `MAX_BORROW_INDEX_RAY`; nothing bounds the product `borrowed * borrow_index` computed inside `scaled_to_original` during accrual. On a large high-decimals book, that product overflows i128 while the index is still below its cap, and every state-mutating entrypoint on that market — `supply`, `withdraw`, `borrow`, `repay`, `liquidate`, `clean_bad_debt`, `flash_loan` — accrues first and panics forever.

### Finding Description
`accrue_step` recomputes utilization via `scaled_to_original(borrowed, borrow_index)`, which is `scaled.mul(index)` in RAY arithmetic — i.e. `borrowed * borrow_index / RAY` — and panics with `GenericError::MathOverflow` when the pre-division product leaves i128 [1](#0-0) . `update_borrow_index` clamps the index at `MAX_BORROW_INDEX_RAY` only *after* multiplying, so the value ceiling is hit first on any book where `borrowed` (RAY-scaled) × `borrow_index` exceeds ~`i128::MAX` [2](#0-1) . Every market mutation runs `global_sync`, which loops `accrue_chunk` until elapsed time is consumed [3](#0-2) , so once the product overflows there is no path that skips accrual — the panic is not a one-transaction DoS but a permanent halt of the book. The harness pins exactly this: after the cliff, `update_indexes`, `withdraw` and `repay` all fail with `MATH_OVERFLOW` while `borrow_index < MAX_BORROW_INDEX_RAY` [4](#0-3) . The invariants doc concedes the gap: "Debt-value overflow can still revert accrual before that ceiling is reached" [5](#0-4) .

Attack path for a single unprivileged address: supply a very large amount of a listed high-decimals asset (`supply`, account_id `0` to create a position), borrow ~98% of it (`borrow`), let time pass while calling the permissionless `update_indexes` to keep accrual running. The attacker needs deep capital (the pinned case uses ~1e18-scale raw supply at 18 decimals), but no privilege, no leaked key, and no oracle manipulation — the freeze is produced entirely by the rate engine's own arithmetic.

### Impact Explanation
Permanent freezing of funds. Once the value product overflows, no supplier can withdraw, no borrower can repay or be liquidated, and no flash loan or bad-debt cleanup can run on that book — all pooled tokens held against it are bricked, analogous to the production halt in the incident. The freeze cannot be undone by governance or an upgrade of calling code, because the panic lives inside the shared accrual step that every entrypoint executes before touching positions.

### Likelihood Explanation
Requires a whale-scale book at sustained high utilization — the pinned reproduction needs ~a billion whole units of an 18-decimal asset at 98% utilization for multiple years before the cliff, and on the steep XLM curve the index passes ~170x before the panic [6](#0-5) . Supply/borrow caps normally bound book size, but a large enough legitimate market (or caps set generously for a high-supply asset) can drift into the fatal region with no admin action. Because it needs extraordinary capital and a long horizon rather than an active trigger, likelihood is low; impact is severe and irreversible once reached — Medium overall.

### Recommendation
Bound the checked product, not just the index: in `accrue_step`/`update_borrow_index`, saturate or early-clamp when `borrowed * borrow_index / RAY` approaches `i128::MAX` (e.g. compute the product with `mul_div` into a wider type or compare `borrowed` against `i128::MAX * RAY / borrow_index` and freeze index growth instead of trapping). Alternatively enforce a listing-time invariant that `max_cap(asset) * MAX_BORROW_INDEX_RAY / RAY` fits i128 with margin, so the cap engages arithmetically before the overflow.

### Proof of Concept
Already pinned by the harness: `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` builds an 18-decimals market, supplies `BILLION * 10^18`, borrows 98%, advances time year by year until `try_update_indexes` fails with `MATH_OVERFLOW`, then asserts `withdraw` and `repay` both fail with the same error while the index remains below `MAX_BORROW_INDEX_RAY` — i.e. the market is permanently frozen and the index cap never fires [4](#0-3) .

### Citations

**File:** common/src/rates/scaling.rs (L14-16)
```rust
pub fn scaled_to_original(env: &Env, scaled: Ray, index: Ray) -> Ray {
    scaled.mul(env, index)
}
```

**File:** common/tests/rates/simulate.rs (L350-367)
```rust
    #[test]
    fn at_the_borrow_index_ceiling_is_sticky_and_accrues_nothing() {
        let env = Env::default();
        let params = make_test_params(&env);
        let cap = Ray::from(crate::constants::MAX_BORROW_INDEX_RAY);
        let step = accrue_step(
            &env,
            &params,
            Ray::from(RAY),
            Ray::from(10 * RAY),
            cap,
            Ray::ONE,
            MILLISECONDS_PER_YEAR,
        );
        assert_eq!(step.borrow_index, cap);
        assert_eq!(step.supply_index, Ray::ONE);
        assert_eq!(step.revenue_shares, Ray::ZERO);
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

**File:** tests/test-harness/tests/controller/large_positions_and_long_horizons.rs (L315-361)
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
}
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
