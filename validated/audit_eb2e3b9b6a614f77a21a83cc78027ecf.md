### Title
Permanent market freeze from unchecked RAY-value overflow during interest accrual - (`common/src/rates/index.rs`)

### Summary
An unprivileged user can create a sufficiently large, highly utilized market whose scaled-book value later exceeds the `i128` RAY domain during interest accrual. Once crossed, `update_indexes`, repayment, withdrawal, liquidation, and other market-touching operations revert before the index cap can clamp growth, permanently freezing all funds in that market. [1](#0-0) [2](#0-1) [3](#0-2) 

### Finding Description
Every existing-market operation first runs `global_sync`, which applies accrued interest through `accrue_step` before executing the requested state transition. [2](#0-1) [4](#0-3) 

`calculate_supplier_rewards` computes both `borrowed * old_borrow_index` and `borrowed * new_borrow_index` as RAY-denominated values before subtracting accrued interest. [3](#0-2) 

The borrow-index ceiling is applied only to the index returned by `update_borrow_index`; it does not prevent the separate book-value multiplication from exceeding `i128::MAX`. [5](#0-4) 

The repository’s regression test demonstrates that a one-billion-whole-token market at 98% utilization reaches the RAY-value ceiling before `MAX_BORROW_INDEX_RAY`, after which both a one-unit withdrawal and a repayment fail with `MathOverflow`. [6](#0-5) 

Because debt repayment itself accrues first, no unprivileged user can reduce the oversized book after the overflow boundary is reached; liquidation and withdrawal are blocked by the same synchronous accrual path. [2](#0-1) [7](#0-6) 

### Impact Explanation
This is a permanent freezing-of-funds condition for the affected `(hub, asset)` pool market. Suppliers cannot withdraw, borrowers cannot repay, liquidators cannot reduce risk, and routine index synchronization fails once the scaled-book value no longer fits the RAY numeric domain. [8](#0-7) 

The impact is market-wide rather than limited to the attacking account because `borrowed`, `supplied`, and the indexes are aggregate market state. [3](#0-2) [9](#0-8) 

### Likelihood Explanation
Likelihood is constrained because the attacker must control an extremely large token position and keep utilization high long enough for compounding to reach the overflow boundary. [10](#0-9) 

The path is nevertheless unprivileged and deterministic: `supply` creates the market book, `borrow` establishes high utilization, and permissionless `update_indexes` eventually reaches the failing accrual. [11](#0-10) 

### Recommendation
Cap or validate market size in value-index space rather than only capping the index itself. Before accepting supply or borrowing, compare `scaled_amount * index` against a conservative headroom below `i128::MAX`, and make accrual gracefully cap accrued book values or permit risk-reducing repayment/withdrawal paths that bypass aggregate supplier-reward computation. [3](#0-2) [4](#0-3) 

The cap checks should account for future index growth up to `MAX_BORROW_INDEX_RAY` and `MAX_SUPPLY_INDEX_RAY`, since token caps alone do not bound `scaled * index`. [5](#0-4) [12](#0-11) 

### Proof of Concept
The checked-in reproduction constructs an 18-decimal market, supplies `1_000_000_000 * 10^18` base units, supplies separate collateral, borrows 98% of the market, advances time until `update_indexes` fails, and then proves withdrawal and repayment both fail with `MathOverflow`. [13](#0-12) 

Conceptually, the unprivileged sequence is:

```rust
supply(
    attacker,
    0,                 // create account
    spoke_id,
    vec![(hub_asset, 1_000_000_000 * 10^18)],
);

supply(
    attacker,
    account_id,
    spoke_id,
    vec![(collateral_hub_asset, sufficient_collateral)],
);

borrow(
    attacker,
    account_id,
    vec![(hub_asset, 980_000_000 * 10^18)],
    None,
);

// Repeat as time passes:
update_indexes(attacker, vec![hub_asset]);
```

At the overflow boundary, `update_indexes` returns `MathOverflow`; subsequent `withdraw` and `repay` calls reach the same accrual before their state changes and also fail. [14](#0-13)

### Citations

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

**File:** contracts/pool/src/interest.rs (L39-52)
```rust
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
```

**File:** common/src/rates/index.rs (L11-18)
```rust
/// Applies `interest_factor` to `old_index` to produce the new borrow index,
/// capped at `MAX_BORROW_INDEX_RAY`.
pub fn update_borrow_index(env: &Env, old_index: Ray, interest_factor: Ray) -> Ray {
    let new_index = old_index.mul(env, interest_factor);
    if new_index.raw() > MAX_BORROW_INDEX_RAY {
        return Ray::from(MAX_BORROW_INDEX_RAY);
    }
    new_index
```

**File:** common/src/rates/index.rs (L21-45)
```rust
/// Grows `old_index` by distributing `rewards_increase` over the total value
/// currently supplied (`supplied * old_index`). The division rounds down.
///
/// Returns `old_index` unchanged if `supplied` or `rewards_increase` is zero,
/// or if the total supplied value is zero. Clamps the result between
/// `old_index` (itself capped at `MAX_SUPPLY_INDEX_RAY`) and
/// `MAX_SUPPLY_INDEX_RAY`, so the returned index never decreases and never
/// exceeds the cap.
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
}
```

**File:** common/src/rates/index.rs (L73-83)
```rust
pub fn calculate_supplier_rewards(
    env: &Env,
    params: &MarketParams,
    borrowed: Ray,
    new_borrow_index: Ray,
    old_borrow_index: Ray,
) -> (Ray, Ray) {
    let old_total_debt = borrowed.mul(env, old_borrow_index);
    let new_total_debt = borrowed.mul(env, new_borrow_index);

    let accrued_interest = new_total_debt.checked_sub(env, old_total_debt);
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
