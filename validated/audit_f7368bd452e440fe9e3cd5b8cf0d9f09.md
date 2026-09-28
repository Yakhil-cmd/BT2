### Title
RAY-scaled index accrual overflows `i128` and permanently freezes a whale market before the index cap engages - (File: common/src/rates/index.rs)

### Summary
The pool's interest accrual multiplies the total scaled share supply (`borrowed`, `supplied`) by the interest index using `Ray::mul`, which panics with `GenericError::MathOverflow` when the product exceeds `i128::MAX` [1](#0-0) [2](#0-1) . Because `supplied`/`borrowed` are stored in RAY scale (a billion whole tokens at 18 decimals is `1e36` raw ray) while `MAX_BORROW_INDEX_RAY` is also `1e36`, the `shares * index` product overflows long before `update_borrow_index`'s cap clamp can fire [3](#0-2) . Once crossed, every market verb accrues first and hits the same panic, so the market is permanently frozen.

### Finding Description
The bug-class analog of CVE-2019-14878 (unchecked failure of a size-capped operation turning into a crash) maps here as: the index-growth code has an explicit ceiling (`MAX_BORROW_INDEX_RAY` / `MAX_SUPPLY_INDEX_RAY`) intended to bound indexes, but the accrual path performs an unchecked `i128` multiplication (`borrowed.mul(env, new_borrow_index)` in `calculate_supplier_rewards`, `supplied.mul(env, old_index)` in `update_supply_index`) whose overflow panics *before* the ceiling can ever protect state [4](#0-3) [5](#0-4) .

`scaled_to_original` (`scaled.mul(env, index)`) is on the critical path of every unscaling used by withdraw, repay, liquidate, and utilization checks [6](#0-5) [7](#0-6) . The repo's own harness test proves the cliff: at ~98% utilization on a steep rate curve, a `1e9`-whole-token 18-decimal market hits `MATH_OVERFLOW` in `update_indexes`, after which both `withdraw` and `repay` fail with the same error because they accrue first [8](#0-7) . Since indexes are monotonic, no subsequent call can ever succeed again.

### Impact Explanation
Permanent freezing of funds. Once `shares * index` exceeds `i128::MAX`, accrual panics inside every entrypoint that touches the market — `supply`, `borrow`, `withdraw`, `repay`, `liquidate`, `clean_bad_debt`, `recapitalize`, `update_indexes` — because all of them accrue first. Suppliers can never withdraw, borrowers can never repay (even voluntarily), and liquidators cannot clear positions. The market becomes a write-once trap holding real token custody, while the debt continues to be unpayable and the pool cannot even write down the bad debt since `clean_bad_debt`/`recapitalize` also accrue. Unlike a transient DoS, the condition is irreversible: the index never decreases, so the overflow threshold once crossed is crossed forever.

### Likelihood Explanation
Medium. Reachability requires a market whose total scaled shares approach `~1e36` ray and sustained high utilization on a steep rate curve — i.e., whale-scale deposits (or a low-price/high-supply token listed with high decimals) plus time for the index to compound past the ~170x headroom between `1e36` and `i128::MAX` [9](#0-8) . An unprivileged attacker can reach it via `supply` + `borrow` (possibly leveraged through `multiply`/flash paths) and then only needs time; alternatively an organic whale market reaches it without any attacker. No privileged action is needed — `update_indexes` is permissionless and any third party can trigger the freezing accrual once the threshold is crossed.

### Recommendation
Perform the products that feed the cap check in a saturating or widened form so the ceiling actually engages: use `mul_div_floor_saturating` (as `update_supply_index` already does for its `grown` computation and `calculate_scaled_cap` does for caps) for `total_supplied_value`, `old_total_debt`, and `new_total_debt` in `update_supply_index`/`calculate_supplier_rewards`, clamping to `i128::MAX` instead of panicking [10](#0-9) . Additionally, bound `supplied`/`borrowed` scaled-share totals against `i128::MAX / MAX_*_INDEX_RAY` at share-mint time (supply/borrow/cap validation), so shares * index can never overflow regardless of index growth; and make the unscale paths (`scaled_to_original`) return a saturating/`Option` result handled gracefully rather than a hard panic for protocol-level accrual.

### Proof of Concept
Reproduced verbatim by the in-repo test `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` [11](#0-10) :

1. List an 18-decimal market on the XLM rate curve; an unprivileged account supplies `1_000_000_000 * 10^18` raw units (scaled shares ≈ `1e36` ray).
2. A second account supplies collateral on another market and borrows ~98% of the whale market (`borrow` entrypoint), pinning utilization at the steep rate segment.
3. Advance ledger time (anyone may call `update_indexes`). After enough compounding, `update_borrow_index` produces a `new_borrow_index` such that `borrowed.mul(env, new_borrow_index)` inside `calculate_supplier_rewards` overflows `i128::MAX` and panics with `MathOverflow` — observed while `borrow_index < MAX_BORROW_INDEX_RAY`, i.e., before the cap can clamp.
4. From that block onward every call that accrues reverts: `try_withdraw(BOB, "BIG18", 1)` → `MATH_OVERFLOW`, `try_repay(ALICE, ...)` → `MATH_OVERFLOW`. Custodied supplier funds are permanently locked; no recover path exists since the index is monotonic.

### Citations

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

**File:** common/src/rates/index.rs (L53-63)
```rust
pub fn supply_index_reward_shortfall(
    env: &Env,
    supplied: Ray,
    old_index: Ray,
    new_index: Ray,
    rewards_increase: Ray,
) -> Ray {
    let distributed = supplied
        .mul(env, new_index)
        .checked_sub(env, supplied.mul(env, old_index));
    rewards_increase.checked_sub(env, distributed)
```

**File:** common/src/rates/index.rs (L80-83)
```rust
    let old_total_debt = borrowed.mul(env, old_borrow_index);
    let new_total_debt = borrowed.mul(env, new_borrow_index);

    let accrued_interest = new_total_debt.checked_sub(env, old_total_debt);
```

**File:** common/src/math/fp.rs (L50-52)
```rust
    pub fn mul(self, env: &Env, other: Ray) -> Ray {
        Ray(fp_core::mul_div_half_up(env, self.0, other.0, RAY))
    }
```

**File:** common/src/constants/pool.rs (L18-23)
```rust
/// Ceiling the borrow index is clamped to after growth, in raw ray units.
pub const MAX_BORROW_INDEX_RAY: i128 = 1_000_000_000_000_000_000_000_000_000_000_000_000;

/// Ceiling the supply index is clamped to after growth, in raw ray units.
/// Equal to [`MAX_BORROW_INDEX_RAY`].
pub const MAX_SUPPLY_INDEX_RAY: i128 = MAX_BORROW_INDEX_RAY;
```

**File:** common/src/rates/scaling.rs (L14-16)
```rust
pub fn scaled_to_original(env: &Env, scaled: Ray, index: Ray) -> Ray {
    scaled.mul(env, index)
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
