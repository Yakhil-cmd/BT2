### Title
RAY-scaled accrual overflows before the index cap and permanently freezes a market - (File: `contracts/pool/src/interest.rs`)

### Summary
A very large, highly utilized market can reach the RAY value domain limit before `MAX_BORROW_INDEX_RAY` engages. The next accrual panics with `MathOverflow`, and because ordinary market operations accrue before mutating, repayment, withdrawal, liquidation, and index synchronization all become unusable.

### Finding Description
`update_borrow_index` caps the borrow index at `MAX_BORROW_INDEX_RAY`, but accrual first evaluates RAY-scaled debt and supply values whose products must fit `i128`. For sufficiently large balances, the unscaled value overflows before the capped index is reached. This is confirmed by the production-flow test `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap`, which observes `MathOverflow` while `borrow_index < MAX_BORROW_INDEX_RAY` and then failed withdrawals and repayments on the same market. [1](#0-0) 

The arithmetic boundary is documented: token-to-RAY upscaling and accrued market values independently have to fit the `i128` RAY domain, and overflow can occur before either index ceiling. [2](#0-1)  The underlying multiplication helpers panic with `GenericError::MathOverflow` when the quotient cannot fit `i128`. [3](#0-2) 

### Impact Explanation
Once crossed, the market cannot accrue, so state-changing paths that begin with accrual revert atomically. Suppliers cannot withdraw, borrowers cannot repay, liquidators cannot liquidate, and keeper-driven `update_indexes` cannot restore the market, permanently freezing all funds held through that market. [4](#0-3) 

### Likelihood Explanation
Reaching the condition requires an unusually large market balance and sustained high utilization, so it is not a low-cost attack. It is nevertheless reachable through unprivileged `supply`, `borrow`, and `update_indexes` calls once balances and accrued indexes approach the documented RAY-domain boundary. [5](#0-4) 

### Recommendation
Rework accrual to bound or reduce RAY-scaled principal before applying index growth, or cap debt/index accrual before evaluating products that can exceed `i128`. At minimum, keep repayments, withdrawals, and liquidations executable by performing loss-bounded partial accrual or a capped-index fallback instead of reverting.

### Proof of Concept
1. Create a high-decimal market with permissive utilization and caps.
2. Supply approximately one billion whole tokens and borrow about 98% of the supplied amount.
3. Advance ledger time while invoking `update_indexes` until the accrued RAY debt value exceeds the `i128` domain before `borrow_index` reaches `MAX_BORROW_INDEX_RAY`.
4. `update_indexes` reverts with `MathOverflow`; subsequent `withdraw`, `repay`, and liquidation paths revert during their mandatory pre-operation accrual. [6](#0-5)

### Citations

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

**File:** docs/reference/formulas.md (L421-437)
```markdown
fee; see [its settlement invariant](invariants.md#inv-strat-04).

| Bound | Consequence |
|---|---|
| Asset decimals 0..=18 | Exact token-to-RAY upscaling. Below 3: collateral only, no flash loans, no liquidation fee, its account's only supply position, at least 2 whole units while in debt |
| Both indexes initially RAY; ceiling 10^36 | 10^9 times initial index; protocol constants |
| Supply-index floor 10^24 | At most 1,000 times the shares minted at index one for the same deposit |
| Borrow APR maximum 2 RAY | 200% annual rate; not a bound on balance growth alone |
| Token-to-RAY input maximum `i128::MAX / 10^(27-d)` | About 170.14 billion whole tokens, before other limits |
| Deposit conversion at the supply-index floor | About 170.14 million whole tokens before scaled-share overflow |

The token-to-RAY maximum is also the admitted cap maximum. Accrued position
values and market totals must independently fit the RAY domain; valid caps and
bounded indexes do not guarantee that future accrual fits. Value overflow can
occur before the index ceiling and block repayment/withdrawal because those
operations accrue first. At the borrow-index ceiling, further accrual produces
no borrower interest. No dedicated ceiling alarm is emitted.
```

**File:** common/src/math/fp_core.rs (L145-159)
```rust
/// Computes `floor(x * y / d)`, rounding toward negative infinity for a negative quotient.
/// Panics with `GenericError::DivisionByZero` if `d == 0`, or with
/// `GenericError::MathOverflow` if the result does not fit in `i128`.
pub fn mul_div_floor(env: &Env, x: i128, y: i128, d: i128) -> i128 {
    require_nonzero_divisor(env, d);
    if let Some(quotient) = x
        .checked_mul(y)
        .and_then(|product| div_floor_i128(product, d))
    {
        return quotient;
    }
    let (x256, y256, d256) = to_i256_operands(env, x, y, d);
    let nonneg = quotient_is_nonnegative(x, y, d);
    to_i128(env, &div_floor_i256(env, &x256.mul(&y256), &d256, nonneg))
}
```
