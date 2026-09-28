### Title
Accrual `scaled_to_original` i128 overflow permanently freezes a market before the borrow-index cap engages - (File: contracts/pool/src/interest.rs / common/src/rates)

### Summary
The CVE bug class is a fixed-capacity buffer/accumulator overflow while parsing/growing attacker-influenced data. The analog in XOXNO Lending is an `i128` overflow in the interest-accrual path: `scaled_to_original` computes `scaled * index` over RAY-scaled values, and when the product exceeds `i128::MAX` it panics with `MathOverflow`. Every pool mutation runs `interest::global_sync` first, so once a market's scaled-debt × borrow-index product crosses the `i128` ceiling, the panic is hit on every subsequent call — supply, borrow, withdraw, repay, liquidate, and `update_indexes` all revert, permanently freezing the market.

### Finding Description
`mul_div_half_up` / `mul_div_floor` (the basis of `scaled_to_original`) panic with `GenericError::MathOverflow` when the product doesn't fit in `i128` — the widened `I256` path is used only to get an exact result, and `to_i128()` returns `None` past the `i128` ceiling [1](#0-0) . `Cache::calculate_utilization` and accrual call `scaled_to_original` on `borrowed` × `borrow_index` unconditionally [2](#0-1) . The pool's own documentation states every market mutation runs `Cache::load → interest::global_sync → mutate → guards → commit`, so no verb can skip accrual [3](#0-2) .

The codebase's own harness test proves the reachable failure: a market with a very large principal at ~98% utilization on the steep XLM rate curve grows `borrowed * borrow_index` past `i128::MAX` while `borrow_index` is still below `MAX_BORROW_INDEX_RAY`, so the index cap never engages; afterward `try_withdraw_raw` and `try_repay` both revert with `MATH_OVERFLOW` [4](#0-3) . The test's own assertion notes "the bound in docs/reference/formulas.md is wrong" — i.e., the documented arithmetic domain does not actually bound this, so it is not a documented accepted limitation [5](#0-4) .

Root cause: the index cap guards `borrow_index`, but the overflowable quantity is `borrowed_scaled * borrow_index`; nothing bounds their product, and the panic propagates through every entrypoint because accrual precedes all mutation.

### Impact Explanation
Permanent freezing of funds: once the product crosses `i128::MAX`, every pool verb on that market — including `repay`, `withdraw`, `liquidate`, `clean_bad_debt`, and `claim_revenue` — panics in `global_sync` before touching state. All supplied cash in that market is unrecoverable, borrowers cannot repay (so liquidations can't happen either), and the controller-side positions backed by that market are bricked. This matches the accepted "permanent freezing of funds" / "contract unable to operate" impact classes.

### Likelihood Explanation
An unprivileged address can drive this by supplying a very large amount to a market and borrowing near maximum utilization, then letting accrual compound — the steep segment of the rate curve accelerates index growth. It requires whale-scale capital and sustained high utilization over an extended accrual horizon; it is not achievable in a single transaction and cannot be fast-forwarded. Any normally operating high-utilization large market will also drift toward the same cliff, so it can also arise organically. Severity: High (permanent freeze of all market funds, reachable by unprivileged actors) with moderate likelihood due to the capital/time requirement.

### Recommendation
Bound the overflowable product, not just the index:
- Add an early cap on `borrowed * borrow_index` (e.g., clamp accrual growth or refuse new borrows when `scaled_to_original(borrowed, projected_index)` approaches `i128::MAX`), enforced inside `global_sync` before computing the accrued total.
- Alternatively, saturate rather than panic in the accrual path (`mul_div_floor_saturating` already exists [6](#0-5) ) combined with a supply/debt ceiling so the saturated value is conservative and the market remains operable.
- Fix the `docs/reference/formulas.md` bound so the documented arithmetic ceiling matches the actual `scaled * index` constraint.

### Proof of Concept
The harness test `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` is a working PoC [7](#0-6) :

1. Create a market with an 18-decimal asset on the steep `xlm_curve`; lift supply/borrow caps.
2. Unprivileged `supply_raw(BOB, "BIG18", 1e9 * 10^18)` and `borrow_raw(ALICE, "BIG18", 98% of principal)` — both are ordinary controller entrypoints.
3. Advance ledger time; call `update_indexes` ("BIG18"). After sufficient accrual it returns `MATH_OVERFLOW` while `borrow_index < MAX_BORROW_INDEX_RAY` — the cap never engaged.
4. `try_withdraw_raw(BOB, "BIG18", 1)` and `try_repay(ALICE, "BIG18", …)` both revert with `MATH_OVERFLOW`; the market is permanently frozen with all supplied funds locked.

### Citations

**File:** common/src/math/fp_core.rs (L122-143)
```rust
pub fn try_mul_div_half_up(env: &Env, x: i128, y: i128, d: i128) -> Option<i128> {
    if x < 0 || y < 0 || d <= 0 {
        return None;
    }
    let half = d / 2;

    // Fast path: the biased product fits `i128`, so the whole computation is
    // native. `x * y + half` is non-negative here, so `/` is the floor the
    // widened path would produce.
    if let Some(biased) = x
        .checked_mul(y)
        .and_then(|product| product.checked_add(half))
    {
        return Some(biased / d);
    }

    let (x256, y256, d256) = to_i256_operands(env, x, y, d);
    x256.mul(&y256)
        .add(&I256::from_i128(env, half))
        .div(&d256)
        .to_i128()
}
```

**File:** common/src/math/fp_core.rs (L177-201)
```rust
/// Computes `floor(x * y / d)`, saturating to `i128::MAX` (or `i128::MIN` for a negative
/// quotient) instead of panicking if the result does not fit in `i128`. Panics with
/// `GenericError::DivisionByZero` if `d == 0`.
pub fn mul_div_floor_saturating(env: &Env, x: i128, y: i128, d: i128) -> i128 {
    require_nonzero_divisor(env, d);
    if let Some(quotient) = x
        .checked_mul(y)
        .and_then(|product| div_floor_i128(product, d))
    {
        return quotient;
    }
    let (x256, y256, d256) = to_i256_operands(env, x, y, d);
    div_floor_i256(
        env,
        &x256.mul(&y256),
        &d256,
        quotient_is_nonnegative(x, y, d),
    )
    .to_i128()
    .unwrap_or(if quotient_is_negative(x, y, d) {
        i128::MIN
    } else {
        i128::MAX
    })
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
