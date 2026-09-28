### Title
Whale market accrual overflows `i128` in `scaled_to_original`, permanently freezing all withdrawals, repayments, and liquidations on the market - (File: common/src/rates/scaling.rs)

### Summary
The bug class from the Avalanche report — an unchecked-adjacent arithmetic overflow in a value-accrual path that only triggers under extreme scale — maps directly onto XOXNO Lending. `Cache::calculate_utilization` and the accrual step value total supply and total debt by calling `scaled_to_original`, which is `Ray::mul` → `fp_core::mul_div_half_up`. When `scaled_shares × index / RAY` no longer fits in `i128`, the `I256`-widened quotient still exceeds `i128` and `mul_div_half_up` panics with `GenericError::MathOverflow`. Because every state-mutating entrypoint accrues first, once a market's RAY-valued book crosses the representable ceiling the whole market is bricked — before the index cap `MAX_BORROW_INDEX_RAY` ever engages.

### Finding Description
`scaled_to_original` is a thin wrapper over `Ray::mul` with no saturation or ceiling guard: `scaled.mul(env, index)` [1](#0-0) . `mul_div_half_up` computes the exact `x * y / d` in `I256` but returns `None` when the quotient itself does not fit `i128`, and the panicking variant converts that to `MathOverflow` [2](#0-1) . `Cache::calculate_utilization` calls it on `self.borrowed × self.borrow_index` and `self.supplied × self.supply_index`, and `accrue_step` (run by `contracts/pool/src/interest.rs` on every mutation and by `update_indexes`) does the same to compute interest [3](#0-2) .

The documentation itself identifies the cliff: "Accrued position values and market totals must independently fit the RAY domain; valid caps and bounded indexes do not guarantee that future accrual fits. Value overflow can occur before the index ceiling and block repayment/withdrawal because those operations accrue first" [4](#0-3) . The admitted cap ceiling is ~170.14 billion whole tokens per asset, so a market near its cap needs only ~170× index growth — well under the `MAX_BORROW_INDEX_RAY = 1e36` (10^9×) cap — for the market-total valuation to leave `i128`.

The harness test proves the end state: after sustained high utilization on a 1-billion-token market, `update_indexes` fails with `MATH_OVERFLOW`, and subsequently `withdraw` and `repay` both fail with `MATH_OVERFLOW` because they accrue first, while `borrow_index < MAX_BORROW_INDEX_RAY` — the cap never engages [5](#0-4) .

### Impact Explanation
Permanent freezing of funds. Once `borrowed × borrow_index` (or `supplied × supply_index`) overflows `i128`, the panic is deterministic and unrecoverable: `update_indexes`, `withdraw`, `repay`, `liquidate`, `borrow`, `supply`, `flash_loan`, `flash_position`, `clean_bad_debt`, `claim_revenue`, and `recapitalize` on that market all route through the accrual path and trap. Suppliers' deposits, borrowers' collateral leg claims, and accrued revenue on that (hub, token) book are locked permanently; bad debt cannot be socialized or recapitalized out of it because `clean_bad_debt`/`recapitalize` also accrue first.

### Likelihood Explanation
Reachable by unprivileged addresses through normal `supply`/`borrow` — no admin action, oracle manipulation, or bad parameters required. Preconditions: a market with caps lifted near the representable maximum (~170B whole tokens), a borrower pushing utilization high, and enough elapsed time at a steep-rate segment for ~170× index growth. On the harness's XLM stress curve (175% max APR) the cliff is reached in well under 40 years; on gentler curves it requires proportionally longer or larger books. The trigger is capital- and time-intensive but purely permissionless: a whale supplier plus a whale borrower (which can be the same actor via collateral) suffices, and growth can also be organic. This matches the Avalanche precedent — extreme-circumstance overflow that still requires handling.

### Recommendation
Guard the accrual path so the cliff degrades gracefully instead of bricking the market:
- Clamp index growth earlier: enforce a market-value ceiling check inside `accrue_step`/`update_indexes` so `borrow_index`/`supply_index` stop growing (or accrual becomes a no-op like the `MAX_BORROW_INDEX_RAY` cap) when `scaled × index` would exceed `i128`, keeping exits usable.
- Alternatively, make the valuation calls in `calculate_utilization` and the interest split use a saturating/`try_` variant so a saturated market blocks only growth verbs (borrow/supply) while `repay`, `withdraw`, and `liquidate` continue.
- Emit an alarm/event when indexes approach the value ceiling, per the noted absence of a ceiling alarm.

### Proof of Concept
The harness already contains an executable PoC: `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` in `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs` (lines 320–361). It (1) supplies 1B whole tokens of an 18-decimal asset, (2) borrows 98% of it, (3) advances time year-by-year until `try_update_indexes_for(&["BIG18"])` returns `errors::MATH_OVERFLOW` — inside `scaled_to_original` during accrual — then asserts `try_withdraw_raw` and `try_repay` both fail with `MATH_OVERFLOW` while `borrow_index < MAX_BORROW_INDEX_RAY`. Every subsequent entrypoint on that market reverts identically; the funds are permanently frozen.

### Citations

**File:** common/src/rates/scaling.rs (L14-16)
```rust
pub fn scaled_to_original(env: &Env, scaled: Ray, index: Ray) -> Ray {
    scaled.mul(env, index)
}
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

**File:** contracts/pool/src/cache/scale.rs (L19-27)
```rust
    pub(crate) fn calculate_utilization(&self) -> Ray {
        if self.supplied == Ray::ZERO {
            return Ray::ZERO;
        }
        let total_borrowed = scaled_to_original(&self.env, self.borrowed, self.borrow_index);
        let total_supplied = scaled_to_original(&self.env, self.supplied, self.supply_index);

        utilization(&self.env, total_borrowed, total_supplied)
    }
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
