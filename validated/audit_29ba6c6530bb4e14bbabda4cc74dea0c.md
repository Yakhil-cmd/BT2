### Title
Unbounded RAY debt valuation overflows and permanently freezes a saturated market - ([File: common/src/rates/index.rs](common/src/rates/index.rs))

### Summary

Accrual computes `borrowed * new_borrow_index` and `supplied * old_supply_index` in RAY before applying the intended index ceilings. [1](#0-0) [2](#0-1) 

When either resulting RAY value exceeds `i128::MAX`, `Ray::mul` panics through `mul_div_half_up`, even though the configured index cap remains below its ceiling. [3](#0-2) [4](#0-3) 

Because every pool mutation loads the market and calls `interest::global_sync` before performing its operation, one overflow makes subsequent repayments, withdrawals, liquidations, bad-debt cleanup, recapitalization, revenue claims, and index updates on that market fail. [5](#0-4) [6](#0-5) 

### Finding Description

The pool stores supply and debt as scaled RAY shares and reconstructs current value by multiplying those shares by the current index. [7](#0-6) 

During each accrual chunk, `accrue_step` receives the scaled books and indexes, then writes the resulting borrow index, supply index, and revenue shares back to the cache. [8](#0-7) 

Inside that step, `calculate_supplier_rewards` separately materializes old and new total debt, while `update_supply_index` materializes total supplied value before calculating index growth. [9](#0-8) [2](#0-1) 

Both products use `Ray::mul`, which returns `MathOverflow` when the exact RAY result cannot fit in `i128`. [3](#0-2) [4](#0-3) 

The configured `MAX_BORROW_INDEX_RAY` and `MAX_SUPPLY_INDEX_RAY` are only ceilings on index values; they do not ensure that `scaled_shares * index / RAY` remains representable. [10](#0-9) [11](#0-10) 

The production integration test demonstrates this exact state with one billion whole-token exposure at 18 decimals and sustained 98% utilization. [12](#0-11) 

That test reaches `MathOverflow` through the permissionless index-update path while `borrow_index` is still below `MAX_BORROW_INDEX_RAY`, then confirms that both withdrawal and repayment fail with the same error. [13](#0-12) 

### Impact Explanation

Once the first accrual hits the unrepresentable RAY value, `last_timestamp` cannot advance because `global_sync` aborts before `mark_accrued`. [14](#0-13) 

Every later operation repeats the same overflowing accrual before its economic mutation, so suppliers cannot withdraw, borrowers cannot repay, liquidators cannot resolve the position, and helpers cannot recover the market. [5](#0-4) [15](#0-14) 

The pool and controller expose user paths for withdrawal, repayment, liquidation, bad-debt cleanup, and index updates, but those controller calls delegate the failing accounting transition to the pool. [16](#0-15) [17](#0-16) 

This is a permanent freezing of user funds absent a privileged code upgrade or other out-of-band recovery, matching the Medium-severity availability impact suggested by the report class. [18](#0-17) 

### Likelihood Explanation

The exploit does not depend on malformed input, privileged parameters, oracle dishonesty, or implementation-level memory corruption. [4](#0-3) 

A sufficiently funded user can create the state through ordinary `supply`, `borrow`, and later `update_indexes` calls by supplying a very large amount of the target asset, supplying collateral, and borrowing enough of it to maintain high utilization. [19](#0-18) [20](#0-19) 

The demonstrated trigger requires extraordinary liquidity and sustained high utilization over multiple years, which substantially limits practical likelihood. [12](#0-11) 

Nevertheless, the amount remains within the protocol’s admitted cap domain for an 18-decimal asset, and the overflow is reached through deterministic checked arithmetic rather than a hypothetical host failure. [21](#0-20) [13](#0-12) 

### Recommendation

Bound index growth by the largest index that keeps the relevant scaled book representable, not merely by the global `10^36` index ceiling. [10](#0-9) 

For nonzero `borrowed`, calculate the new debt value using a checked or saturating representation and clamp `new_borrow_index` to at most `floor(i128::MAX * RAY / borrowed.raw())`; apply the equivalent book-dependent bound to `new_supply_index` for nonzero `supplied`. [11](#0-10) [2](#0-1) 

Alternatively, enter an explicit arithmetic-limited market state when further interest would exceed the RAY value domain, while still permitting debt repayment, collateral withdrawal subject to solvency, liquidation, and recapitalization without additional interest accrual. [22](#0-21) 

Add a regression test proving that after the value-domain boundary is reached, `update_indexes` succeeds or enters the explicit bounded state and that `repay`, `withdraw`, `liquidate`, `clean_bad_debt`, `recapitalize`, and `claim_revenue` do not all revert solely from accrual. [23](#0-22) 

### Proof of Concept

The repository already contains a deterministic proof in `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap`. [24](#0-23) 

```rust
let principal = BILLION * 10i128.pow(18); // 1e27 units = 1 billion 18-decimal tokens
t.supply_raw(BOB, "BIG18", principal);
let debt = principal / 100 * 98;
t.supply_raw(ALICE, "COL", BILLION * 10_000_000 * 3);
t.borrow_raw(ALICE, "BIG18", debt);
``` [25](#0-24) 

The test then advances time yearly and calls the market index update until `try_update_indexes_for(&["BIG18"])` returns `MathOverflow`. [26](#0-25) 

```rust
assert!(last.borrow_index < MAX_BORROW_INDEX_RAY);
assert_contract_error(t.try_withdraw_raw(BOB, "BIG18", 1), errors::MATH_OVERFLOW);
assert_contract_error(t.try_repay(ALICE, "BIG18", 1.0), errors::MATH_OVERFLOW);
``` [27](#0-26) 

The failed borrow index remains below the intended global ceiling, proving that the panic comes from unrepresentable total value rather than from reaching `MAX_BORROW_INDEX_RAY`. [28](#0-27)

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

**File:** common/src/rates/index.rs (L29-35)
```rust
pub fn update_supply_index(env: &Env, supplied: Ray, old_index: Ray, rewards_increase: Ray) -> Ray {
    if supplied == Ray::ZERO || rewards_increase == Ray::ZERO {
        return old_index;
    }

    let total_supplied_value = supplied.mul(env, old_index);

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

**File:** common/src/math/fp.rs (L49-52)
```rust
    /// Multiplies two ray values, rounding the result half up.
    pub fn mul(self, env: &Env, other: Ray) -> Ray {
        Ray(fp_core::mul_div_half_up(env, self.0, other.0, RAY))
    }
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

**File:** contracts/pool/src/ops/mod.rs (L29-40)
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
}
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

**File:** contracts/pool/src/interest.rs (L39-53)
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
}
```

**File:** contracts/pool/src/cache/mod.rs (L30-41)
```rust
pub(crate) struct Cache {
    env: Env,
    hub_asset: HubAssetKey,
    params: MarketParams,
    last_timestamp: u64,
    current_timestamp: u64,
    supplied: Ray,
    borrowed: Ray,
    revenue: Ray,
    borrow_index: Ray,
    supply_index: Ray,
    cash: i128,
```

**File:** common/src/constants/pool.rs (L18-23)
```rust
/// Ceiling the borrow index is clamped to after growth, in raw ray units.
pub const MAX_BORROW_INDEX_RAY: i128 = 1_000_000_000_000_000_000_000_000_000_000_000_000;

/// Ceiling the supply index is clamped to after growth, in raw ray units.
/// Equal to [`MAX_BORROW_INDEX_RAY`].
pub const MAX_SUPPLY_INDEX_RAY: i128 = MAX_BORROW_INDEX_RAY;
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

**File:** contracts/controller/src/lib.rs (L120-158)
```rust
    fn withdraw(
        env: Env,
        caller: Address,
        account_id: u64,
        withdrawals: Vec<(HubAssetKey, i128)>,
        to: Option<Address>,
    ) -> Vec<(HubAssetKey, i128)> {
        positions::process_withdraw(&env, &caller, account_id, &withdrawals, to)
    }

    /// Repays `account_id`'s debt using measured payments from the caller.
    /// Anyone may repay; excess payments are refunded to the caller.
    fn repay(env: Env, caller: Address, account_id: u64, payments: Vec<(HubAssetKey, i128)>) {
        positions::process_repay(&env, &caller, account_id, &payments);
    }

    /// Repays debt and seizes collateral at a health-factor-based bonus.
    /// Permissionless, including self-liquidation; requires liquidator authorization.
    /// Residual bad debt is socialized only at or below the collateral dust cap.
    ///
    /// `Transfer` pays pool cash and returns `0`. `Credit(id)` moves net supply
    /// shares to a different, authorized Normal-mode account on the same spoke;
    /// `Credit(0)` creates one. Credit mode needs no free collateral liquidity
    /// and returns the receiving account id.
    fn liquidate(
        env: Env,
        liquidator: Address,
        account_id: u64,
        debt_payments: Vec<(HubAssetKey, i128)>,
        seize_mode: SeizeMode,
    ) -> u64 {
        positions::liquidation::process_liquidation(
            &env,
            &liquidator,
            account_id,
            &debt_payments,
            seize_mode,
        )
    }
```

**File:** contracts/controller/src/external/pool.rs (L21-37)
```rust
/// The controller must transfer and measure receipts before this call.
pub(crate) fn pool_supply_call(
    env: &Env,
    pool_addr: &Address,
    entries: &Vec<PoolSupplyEntry>,
) -> Vec<PoolPositionMutation> {
    LiquidityPoolClient::new(env, pool_addr).supply(entries)
}

/// Mints scaled debt and transfers borrowed assets to `receiver`.
pub(crate) fn pool_borrow_call(
    env: &Env,
    pool_addr: &Address,
    receiver: &Address,
    entries: &Vec<PoolBorrowEntry>,
) -> Vec<PoolPositionMutation> {
    LiquidityPoolClient::new(env, pool_addr).borrow(receiver, entries)
```

**File:** contracts/controller/src/external/pool.rs (L54-71)
```rust
pub(crate) fn pool_withdraw_call(
    env: &Env,
    pool_addr: &Address,
    receiver: &Address,
    is_liquidation: bool,
    entries: &Vec<PoolWithdrawEntry>,
) -> Vec<PoolPositionMutation> {
    LiquidityPoolClient::new(env, pool_addr).withdraw(receiver, &is_liquidation, entries)
}

/// Burns debt against prefunded payments and refunds overpayment to `payer`.
pub(crate) fn pool_repay_call(
    env: &Env,
    pool_addr: &Address,
    payer: &Address,
    actions: &Vec<PoolAction>,
) -> Vec<PoolPositionMutation> {
    LiquidityPoolClient::new(env, pool_addr).repay(payer, actions)
```

**File:** contracts/pool/src/lib.rs (L31-38)
```rust
//! ## Security notes
//!
//! - Every mutator requires the owner through `#[only_owner]`; views are public.
//! - Cash is an accounting book, separate from the token balance. A flash loan
//!   checks the token balance after payout, after the callback and after
//!   repayment.
//! - Write paths extend the instance TTL. Every market load, views included,
//!   extends the market's params and state TTL.
```

**File:** docs/reference/formulas.md (L425-437)
```markdown
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
