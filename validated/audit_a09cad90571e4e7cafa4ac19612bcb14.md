### Title
Accrual overflow permanently freezes an oversized high-utilization market - (File: common/src/rates/index.rs)

### Summary

A sufficiently large market left at high utilization can reach a state where every subsequent market operation panics with `MathOverflow`. The immediate cause is accrual calculating `borrowed * borrow_index` and related RAY-denominated values in `i128` before the borrow-index ceiling can provide protection. Once that product no longer fits, `update_indexes`, repayment, withdrawal, liquidation, and other paths that sync the market all revert, permanently freezing the market's funds. [1](#0-0) [2](#0-1) 

### Finding Description

`Controller::supply` and `Controller::borrow` are reachable by an unprivileged account owner or delegate and can create a very large supplied/borrowed position subject only to the configured caps and token supply. [3](#0-2) 

Every pool mutation first calls `ops::synced_market`, which loads the market and invokes `interest::global_sync`. [2](#0-1)  `global_sync` iteratively calls `accrue_step` for elapsed time chunks. [4](#0-3)  During each accrual step, `calculate_supplier_rewards` computes both the old and new total debt as `borrowed.mul(index)` and subtracts them. [1](#0-0)  The multiplication is checked and panics with `GenericError::MathOverflow` when the resulting RAY value does not fit in `i128`. [5](#0-4) 

The protocol bounds the borrow index itself at `MAX_BORROW_INDEX_RAY`, but that cap is applied only to the returned index and does not prevent `borrowed * index` from exceeding the `i128` value domain first. [6](#0-5)  Project documentation explicitly recognizes that accrued market totals can overflow before the index ceiling and block repayment and withdrawal because those operations accrue first. [7](#0-6) 

### Impact Explanation

This is a permanent freeze of all funds in the affected market. Suppliers cannot withdraw, borrowers cannot repay, liquidators cannot liquidate, and other recovery paths that synchronize the same market fail on the same accrual panic. The regression test demonstrates this terminal state by asserting that both `withdraw` and `repay` revert with `MathOverflow` after the overflow condition is reached. [8](#0-7) 

### Likelihood Explanation

Likelihood is medium-low because the attacker must establish an extremely large market and leave it at sustained high utilization for multiple years; the repository's proof uses one billion whole 18-decimal tokens and a 98% borrow. [9](#0-8)  However, no privileged action is required at execution time: an account can supply the market through `supply(caller, 0, spoke_id, [(hub_asset, amount)])` and borrow through `borrow(caller, account_id, [(hub_asset, amount)], to)`, after which ordinary passage of time reaches the unrecoverable state. [3](#0-2) 

### Recommendation

Bound accrued position and market values before multiplying scaled shares by indexes. In particular:

- Add a pre-accrual solvency bound such as `borrowed <= i128::MAX / borrow_index` and supply-side equivalents.
- Store or calculate totals in a wider representation where practical, or split accrual into bounded value deltas that cannot overflow.
- Keep a recovery operation that can reduce `borrowed` or `supplied` shares without first computing the overflowing total.
- Add explicit market-size limits tied to `i128::MAX / MAX_BORROW_INDEX_RAY`, rather than admitting amounts that can only fail after index growth.

### Proof of Concept

The existing deterministic test `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` provides the proof:

1. Create an 18-decimal market using the steep `xlm_curve` parameters and a collateral market.
2. Supply `1_000_000_000 * 10^18` base units of `BIG18`.
3. Supply sufficient collateral and borrow `98%` of that amount.
4. Advance time in one-year increments and call `update_indexes` until it returns `MathOverflow`.
5. Observe `borrow_index < MAX_BORROW_INDEX_RAY`, proving the index cap did not prevent the failure.
6. Call `withdraw` for one unit and `repay` for a small amount; both revert with `MathOverflow`.

The test comments and assertions document the resulting freeze: no repay, no withdraw, and no liquidation. [8](#0-7)

### Citations

**File:** common/src/rates/index.rs (L11-19)
```rust
/// Applies `interest_factor` to `old_index` to produce the new borrow index,
/// capped at `MAX_BORROW_INDEX_RAY`.
pub fn update_borrow_index(env: &Env, old_index: Ray, interest_factor: Ray) -> Ray {
    let new_index = old_index.mul(env, interest_factor);
    if new_index.raw() > MAX_BORROW_INDEX_RAY {
        return Ray::from(MAX_BORROW_INDEX_RAY);
    }
    new_index
}
```

**File:** common/src/rates/index.rs (L73-88)
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

    let protocol_fee = params.reserve_factor.apply_to_ray(env, accrued_interest);
    let supplier_rewards = accrued_interest.checked_sub(env, protocol_fee);

    (supplier_rewards, protocol_fee)
```

**File:** contracts/pool/src/ops/mod.rs (L29-39)
```rust
/// Loads a market cache and accrues interest through the current ledger time.
pub(crate) fn synced_market(env: &Env, hub_asset: &HubAssetKey) -> Cache {
    let mut cache = Cache::load(env, hub_asset);
    interest::global_sync(env, &mut cache);
    cache
}

/// Renews instance TTL, then loads and accrues the market.
pub(crate) fn renewed_market(env: &Env, hub_asset: &HubAssetKey) -> Cache {
    renew_instance(env);
    synced_market(env, hub_asset)
```

**File:** contracts/controller/src/lib.rs (L90-115)
```rust
    /// Supplies `assets` as collateral and returns the account id; `account_id = 0`
    /// creates an account in `spoke_id`. Third parties may only top up existing
    /// supply positions; owners and delegates may add assets.
    #[when_not_paused]
    fn supply(
        env: Env,
        caller: Address,
        account_id: u64,
        spoke_id: u32,
        assets: Vec<(HubAssetKey, i128)>,
    ) -> u64 {
        positions::process_supply(&env, &caller, account_id, spoke_id, &assets)
    }

    /// Borrows against `account_id`'s collateral, paying `to` or the caller.
    /// Requires owner or delegate authorization and post-borrow solvency.
    #[when_not_paused]
    fn borrow(
        env: Env,
        caller: Address,
        account_id: u64,
        borrows: Vec<(HubAssetKey, i128)>,
        to: Option<Address>,
    ) {
        positions::process_borrow(&env, &caller, account_id, &borrows, to);
    }
```

**File:** contracts/pool/src/interest.rs (L20-52)
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

**File:** docs/reference/formulas.md (L432-437)
```markdown
The token-to-RAY maximum is also the admitted cap maximum. Accrued position
values and market totals must independently fit the RAY domain; valid caps and
bounded indexes do not guarantee that future accrual fits. Value overflow can
occur before the index ceiling and block repayment/withdrawal because those
operations accrue first. At the borrow-index ceiling, further accrual produces
no borrower interest. No dedicated ceiling alarm is emitted.
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
