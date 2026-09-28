### Title
Accrued debt-value multiplication overflows before the borrow-index cap, permanently freezing a market - (`common/src/rates/index.rs`)

### Summary
The accrual path assumes `borrowed * new_borrow_index / RAY` remains representable in `i128`. A sufficiently large market can push the borrow index high enough for this product to revert even though `new_borrow_index` is still below `MAX_BORROW_INDEX_RAY`. Because every user-facing market operation accrues interest before repayment, withdrawal, liquidation, or settlement, reaching this state permanently freezes the market. [1](#0-0) [2](#0-1) 

### Finding Description
`calculate_supplier_rewards` computes both `borrowed.mul(env, old_borrow_index)` and `borrowed.mul(env, new_borrow_index)`. `Ray::mul` calls `mul_div_half_up`, which panics with `MathOverflow` when the rounded product does not fit in `i128`. [3](#0-2) [4](#0-3) [5](#0-4) 

The borrow index is capped only after this multiplication in `update_borrow_index`; nothing caps the derived total-debt value used by `calculate_supplier_rewards`. Thus the protocol can reach a state where the index itself remains below `MAX_BORROW_INDEX_RAY`, but the market's scaled debt value is unrepresentable. [6](#0-5) 

This is reachable through ordinary unprivileged market use: an attacker or combination of users supplies a very large amount and borrows a large fraction through controller `supply` and `borrow`; once the pool's `borrowed` scaled amount and later `borrow_index` satisfy `borrowed * borrow_index / RAY > i128::MAX`, the next accrual panics. The repository already demonstrates this shape with a one-billion-whole-token market at 98% utilization: `update_indexes` fails with `MathOverflow`, and then both `withdraw` and `repay` fail because they accrue first. [7](#0-6) 

### Impact Explanation
The failure is a permanent freezing of funds for the affected market. Suppliers cannot withdraw and borrowers cannot repay because `Cache::load`/market operation renewal runs `global_sync` before the requested mutation. Liquidation and bad-debt cleanup also depend on the same accrued market state, so the usual insolvency recovery paths cannot operate after the threshold is crossed. [2](#0-1) [8](#0-7) [9](#0-8) 

The state cannot be unwound by a smaller transaction: decreasing `amount` does not decrease the stored aggregate `borrowed` shares used in accrual. Any call that advances time re-enters the overflowing multiplication before it can reduce debt. [10](#0-9) 

### Likelihood Explanation
The condition requires a very large representable market and enough index growth for aggregate debt value to exceed the `i128` range. The repository's own long-horizon test shows this can occur before `MAX_BORROW_INDEX_RAY` engages, with the market frozen afterward. [11](#0-10)  The documented numeric limits also acknowledge that accrued market totals can overflow before the index ceiling and block repayment and withdrawal. [12](#0-11) 

### Recommendation
Do not derive interest by multiplying stored scaled debt by a post-clamp index in `i128` before checking representability. One fix is to compute `old_total_debt`, `new_total_debt`, and `accrued_interest` through an `I256` intermediate and explicitly clamp or bound the result before converting back to `Ray`. Alternatively, detect the impending value-overflow before updating `borrow_index`, clamp the index at the largest value for which `borrowed * index / RAY` remains representable, and make that clamp part of the market's persisted index domain.

The same protection should be applied consistently to `calculate_supplier_rewards`, `update_supply_index`, utilization calculation, and any other accrual path that converts aggregate scaled shares back to RAY value, since `supplied.mul(env, old_index)` has the same structural overflow condition. [13](#0-12) [14](#0-13) 

### Proof of Concept
1. Create a high-decimals market whose configured caps admit approximately `1_000_000_000` whole tokens.
2. Have one account supply approximately `1_000_000_000 * 10^18` base units.
3. Have a borrower provide sufficient collateral and borrow approximately 98% of that market.
4. Advance ledger time until `borrowed_scaled * borrow_index / RAY` exceeds `i128::MAX`, while the index remains below `MAX_BORROW_INDEX_RAY`.
5. Invoke controller `update_indexes` for the market. `global_sync` calls `accrue_step`; `calculate_supplier_rewards` panics in `borrowed.mul(env, new_borrow_index)`.
6. Invoke `repay` or `withdraw` for any positive amount. Both paths accrue first and fail with the same `MathOverflow`, leaving the market permanently frozen.

The repository contains this executable scenario in `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap`; it asserts that index accrual fails before the index cap and that both one-unit withdrawal and repayment subsequently revert with `MathOverflow`. [7](#0-6)

### Citations

**File:** common/src/rates/index.rs (L13-18)
```rust
pub fn update_borrow_index(env: &Env, old_index: Ray, interest_factor: Ray) -> Ray {
    let new_index = old_index.mul(env, interest_factor);
    if new_index.raw() > MAX_BORROW_INDEX_RAY {
        return Ray::from(MAX_BORROW_INDEX_RAY);
    }
    new_index
```

**File:** common/src/rates/index.rs (L29-44)
```rust
pub fn update_supply_index(env: &Env, supplied: Ray, old_index: Ray, rewards_increase: Ray) -> Ray {
    if supplied == Ray::ZERO || rewards_increase == Ray::ZERO {
        return old_index;
    }

    let total_supplied_value = supplied.mul(env, old_index);

    if total_supplied_value == Ray::ZERO {
        return old_index;
    }

    let new_value = total_supplied_value.checked_add(env, rewards_increase);
    let grown = fp_core::mul_div_floor_saturating(env, new_value.raw(), RAY, supplied.raw());

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

**File:** contracts/pool/src/interest.rs (L20-32)
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
```

**File:** common/src/math/fp.rs (L49-56)
```rust
    /// Multiplies two ray values, rounding the result half up.
    pub fn mul(self, env: &Env, other: Ray) -> Ray {
        Ray(fp_core::mul_div_half_up(env, self.0, other.0, RAY))
    }

    /// Divides this value by `other`, rounding the result half up.
    pub fn div(self, env: &Env, other: Ray) -> Ray {
        Ray(fp_core::mul_div_half_up(env, self.0, RAY, other.0))
```

**File:** common/src/math/fp_core.rs (L104-118)
```rust
/// Computes `x * y / d` rounded half up. Requires `x >= 0`, `y >= 0`, and `d > 0`; a
/// `debug_assert` checks this in debug builds. Panics with `GenericError::DivisionByZero` if
/// `d == 0`, and with `GenericError::MathOverflow` if any other precondition is violated or if
/// the result does not fit in `i128`.
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

**File:** contracts/pool/src/ops/withdraw.rs (L63-80)
```rust
    let (mut cache, position) = ops::load_leg(env, &entry.action);

    let (burned, gross_amount) = resolve_close_or_partial(&cache, entry.action.amount, position);
    // Burn first: `protocol_fee_shares` caps the fee mint at `i128::MAX - supplied`.
    let remaining = burn_position(env, &mut cache, position, burned);
    let net_transfer = withhold_liquidation_fee(
        env,
        &mut cache,
        gross_amount,
        is_liquidation,
        entry.protocol_fee,
    );

    // A footprint-only close must not add a utilization gate to same-market
    // net settlement: it burns no shares and moves no cash.
    let empty_close = position.raw() == 0 && entry.action.amount == i128::MAX;
    gate_and_debit(env, &mut cache, net_transfer, is_liquidation || empty_close);

```

**File:** contracts/pool/src/ops/repay.rs (L40-55)
```rust
pub(crate) fn accounting(env: &Env, action: &PoolAction) -> RepayOutcome {
    let (mut cache, position) = ops::load_leg(env, action);
    let amount = action.amount;

    let (burned, overpayment) = cache.resolve_repay(amount, position);
    let net_repay = amount
        .checked_sub(overpayment)
        .unwrap_or_else(|| panic_with_error!(env, GenericError::MathOverflow));
    assert_with_error!(
        env,
        net_repay == 0 || burned.raw() > 0,
        GenericError::RepayRoundsToZeroShares
    );

    let position = position.checked_sub(env, burned);
    cache.burn_debt(burned);
```

**File:** common/src/rates/simulate.rs (L60-71)
```rust
    let borrowed_original = scaled_to_original(env, borrowed, borrow_index);
    let supplied_original = scaled_to_original(env, supplied, supply_index);
    let util = utilization(env, borrowed_original, supplied_original);
    let borrow_rate = calculate_borrow_rate(env, util, params);
    let interest_factor = compound_interest(env, borrow_rate, delta_ms);

    let new_borrow_index = update_borrow_index(env, borrow_index, interest_factor);

    let (supplier_rewards, protocol_fee) =
        calculate_supplier_rewards(env, params, borrowed, new_borrow_index, borrow_index);

    let new_supply_index = update_supply_index(env, supplied, supply_index, supplier_rewards);
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
