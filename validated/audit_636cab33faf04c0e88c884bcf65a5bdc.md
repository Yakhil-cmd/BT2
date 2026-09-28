### Title
Permanent market freeze via i128 overflow in accrued-debt valuation before the borrow-index cap engages - (File: common/src/rates/index.rs)

### Summary
Analog of the ALPINE-CVE-2020-12762 bug class (integer overflow corrupting computation on large input): in XOXNO Lending, the RAY-denominated debt valuation `borrowed * borrow_index` overflows `i128` well before `MAX_BORROW_INDEX_RAY` can cap index growth. Once the product crosses `i128::MAX`, every state-changing entrypoint that accrues the market panics with `MathOverflow`, permanently freezing all supplied and borrowed funds in that market. The panic occurs inside `Ray::mul` → `fp_core::mul_div_half_up`, reached through `scaled_to_original`/`calculate_supplier_rewards` during accrual. [1](#0-0) [2](#0-1) [3](#0-2) 

### Finding Description
The protocol maintains debt as scaled RAY shares and values it as `scaled_debt * borrow_index / RAY`. Both factors are i128. The protocol-wide balance ceiling is `i128::MAX / RAY ≈ 1.7e11` whole tokens, so a whale-scale market can hold scaled debt near `1e36` raw ray. The borrow index is nominally capped by `update_borrow_index` at `MAX_BORROW_INDEX_RAY`, but the clamp happens **after** the multiplication and only bounds the index — it does not bound the *product* `borrowed * index` used later in the same accrual step. [4](#0-3) 

In `calculate_supplier_rewards`, `borrowed.mul(env, new_borrow_index)` computes `scaled * index / RAY`; the intermediate `scaled * index + RAY/2` exceeds `i128::MAX`, widens to `I256`, and the quotient still exceeds `i128::MAX`, so `to_i128()` returns `None` and `mul_div_half_up` panics with `GenericError::MathOverflow`. [5](#0-4)  The same panic site sits in `Cache::calculate_utilization`, which accrual calls to recompute rates each chunk. [6](#0-5) 

Because every pool verb (supply, borrow, withdraw, repay, liquidate, clean_bad_debt) accrues the market first, the overflow is a latch: once crossed, no caller can ever touch the market again. The repository's own horizon test encodes this exact cliff: at 98% utilization on the steep XLM curve with a `1e9` whole-token, 18-decimal market, the index crosses the ~170x value ceiling while `borrow_index < MAX_BORROW_INDEX_RAY`, after which `withdraw` and `repay` both revert with `MATH_OVERFLOW`. [7](#0-6) 

### Impact Explanation
Permanent freezing of funds. All suppliers' deposits in the affected market become unwithdrawable, borrowers cannot repay, liquidators cannot liquidate, and `clean_bad_debt`/`recapitalize` accrue first and also revert. An attacker who supplies the whale position and borrows ~98% of it retains the borrowed principal; the supplier-side funds are bricked forever. The borrow-index cap — the protocol's intended guard against unbounded accrual — never engages because the value ceiling is hit at index ≈ 173 RAY, orders of magnitude below `MAX_BORROW_INDEX_RAY`. [8](#0-7) 

### Likelihood Explanation
Reachable entirely through unprivileged entrypoints: `supply` (large amount), `borrow` at high utilization, then passive waiting while anyone's `update_indexes` call accrues. Two caveats temper likelihood:

- The setup requires whale-scale capital — roughly `1e9` whole tokens of an 18-decimal asset — and market supply/borrow caps must permit it (`lift_caps` is used in the test; on a real listing this depends on governance-set caps, which are a parameter choice). [9](#0-8) 
- Accrual must run uninterrupted at high utilization until the index crosses `value_ceiling / scaled_debt`; utilization resets the curve via `calculate_utilization`, so the attacker must keep utilization high.

Given a high-cap, high-decimals listing at sustained high utilization, the freeze is deterministic, not probabilistic — the index is monotonic and cannot retreat below the overflow threshold. [10](#0-9) 

### Recommendation
Bound the *product*, not the index:

1. In `update_borrow_index` (and accrual callers), clamp `new_index` to `min(MAX_BORROW_INDEX_RAY, i128::MAX / borrowed * RAY)` so `borrowed * index` can never overflow — at the clamp, accrual stops growing debt rather than freezing.
2. Alternatively, make `calculate_supplier_rewards`/`scaled_to_original` saturate: when the widened quotient exceeds `i128::MAX`, treat debt value as the representable maximum and let the index cap logic proceed, keeping repay/withdraw/liquidate live.
3. Optionally enforce at listing time a per-market invariant `max_supply_cap_scaled * MAX_BORROW_INDEX_RAY ≤ i128::MAX`, analogous to the existing `require_cap_within_asset_domain` check. [11](#0-10) 

### Proof of Concept
The codebase already contains a harness test demonstrating the full path. Reproducing it manually:

1. `supply(BOB, BIG18, 1_000_000_000 * 10^18)` — scaled supply ≈ `1e36` raw ray.
2. `supply(ALICE, COL, …)` then `borrow(ALICE, BIG18, 0.98 * principal)` — scaled debt ≈ `0.98e36`.
3. Advance time ~1 year chunks and call `update_indexes("BIG18")` until `borrowed * borrow_index + RAY/2 > i128::MAX` — at 98% utilization on the XLM curve this occurs at index ≈ 173 RAY, far below `MAX_BORROW_INDEX_RAY = 1e36`.
4. The accrual panics inside `calculate_supplier_rewards` → `borrowed.mul(new_index)` → `mul_div_half_up` → `MathOverflow`.
5. `withdraw(BOB, BIG18, …)`, `repay(ALICE, BIG18, …)`, `liquidate`, and `clean_bad_debt` all revert with the same error permanently. [12](#0-11)

### Citations

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

**File:** common/src/rates/index.rs (L43-44)
```rust
    let bounded_old = old_index.raw().min(MAX_SUPPLY_INDEX_RAY);
    Ray::from(grown.min(MAX_SUPPLY_INDEX_RAY).max(bounded_old))
```

**File:** common/src/rates/index.rs (L80-86)
```rust
    let old_total_debt = borrowed.mul(env, old_borrow_index);
    let new_total_debt = borrowed.mul(env, new_borrow_index);

    let accrued_interest = new_total_debt.checked_sub(env, old_total_debt);

    let protocol_fee = params.reserve_factor.apply_to_ray(env, accrued_interest);
    let supplier_rewards = accrued_interest.checked_sub(env, protocol_fee);
```

**File:** common/src/rates/scaling.rs (L14-16)
```rust
pub fn scaled_to_original(env: &Env, scaled: Ray, index: Ray) -> Ray {
    scaled.mul(env, index)
}
```

**File:** common/src/rates/scaling.rs (L20-25)
```rust
/// The division saturates at `i128::MAX` instead of panicking, so the cap check
/// fails open rather than trapping an entry path. The asset-to-RAY
/// rescale still panics on overflow; listings validate caps with
/// [`crate::validation::require_cap_within_asset_domain`]. Position accounting
/// uses [`calculate_scaled_supply`] and [`calculate_scaled_borrow`], which panic
/// on overflow.
```

**File:** common/src/rates/scaling.rs (L26-33)
```rust
pub fn calculate_scaled_cap(env: &Env, cap: i128, decimals: u32, index: Ray) -> Ray {
    Ray::from(fp_core::mul_div_floor_saturating(
        env,
        Ray::from_asset(env, cap, decimals).raw(),
        RAY,
        index.raw(),
    ))
}
```

**File:** common/src/math/fp.rs (L50-52)
```rust
    pub fn mul(self, env: &Env, other: Ray) -> Ray {
        Ray(fp_core::mul_div_half_up(env, self.0, other.0, RAY))
    }
```

**File:** common/src/math/fp_core.rs (L138-143)
```rust
    let (x256, y256, d256) = to_i256_operands(env, x, y, d);
    x256.mul(&y256)
        .add(&I256::from_i128(env, half))
        .div(&d256)
        .to_i128()
}
```

**File:** contracts/pool/src/cache/scale.rs (L23-26)
```rust
        let total_borrowed = scaled_to_original(&self.env, self.borrowed, self.borrow_index);
        let total_supplied = scaled_to_original(&self.env, self.supplied, self.supply_index);

        utilization(&self.env, total_borrowed, total_supplied)
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

**File:** common/tests/rates/index.rs (L496-517)
```rust
#[test]
fn test_borrow_index_at_the_ceiling_multiplies_without_overflow() {
    let env = Env::default();

    // `update_borrow_index` multiplies before it clamps, so the pre-clamp
    // product at the ceiling times the largest reachable chunk factor is the
    // real overflow site. It must stay inside i128 with room to spare.
    let factor = max_chunk_growth_factor(&env, MAX_BORROW_RATE_RAY);
    let at_ceiling = Ray::from(MAX_BORROW_INDEX_RAY);

    let product = at_ceiling.mul(&env, factor);
    assert!(product.raw() > MAX_BORROW_INDEX_RAY);
    assert!(
        product.raw() < i128::MAX / 20,
        "pre-clamp headroom above the ceiling fell below 20x: {}",
        product.raw()
    );

    assert_eq!(
        update_borrow_index(&env, at_ceiling, factor).raw(),
        MAX_BORROW_INDEX_RAY,
    );
```
