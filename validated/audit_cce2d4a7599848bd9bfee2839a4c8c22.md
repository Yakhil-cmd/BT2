### Title
Unbounded share-index accrual overflows `i128` and permanently freezes a market - ([File: common/src/rates/simulate.rs])

### Summary
A sufficiently large market can grow its borrow index until `borrowed_shares * borrow_index` no longer fits in `i128`, after which every operation that accrues interest reverts with `MathOverflow` before any state-changing logic can run. The result is permanent freezing of supplier, borrower, liquidator, and keeper access to that market. [1](#0-0) [2](#0-1) [3](#0-2) 

### Finding Description
`accrue_step` first converts aggregate scaled debt and supply into RAY-valued originals by calling `scaled_to_original` for `borrowed * borrow_index` and `supplied * supply_index`. [4](#0-3) 

`scaled_to_original` delegates to `Ray::mul`, which uses `mul_div_half_up` and panics with `GenericError::MathOverflow` when the exact result cannot fit in `i128`. [5](#0-4) [6](#0-5) [7](#0-6) 

Although `update_borrow_index` caps the index at `MAX_BORROW_INDEX_RAY`, accrual computes the debt and supply values before that cap can be applied, so a large share count can overflow below the nominal index ceiling. [1](#0-0) [8](#0-7) 

Every pool mutation path loads an interest-synced cache, and `synced_market` always invokes `interest::global_sync` before the operation-specific logic. [2](#0-1) 

`global_sync` iterates over all elapsed accrual chunks and invokes `accrue_chunk`, while permissionless controller-driven `update_indexes` reaches the same accrual loop through `ops::market::accrue`. [9](#0-8) [10](#0-9) 

Because `last_timestamp` is never committed past the overflow point, every later call recomputes the same or a larger unrepresentable product and traps again. [11](#0-10) [12](#0-11) 

### Impact Explanation
Once the product crosses the `i128` domain, `withdraw`, `repay`, liquidation settlement, bad-debt cleanup, recapitalization, and keeper index updates all fail before they can mutate the affected market. [2](#0-1) [13](#0-12) 

The regression test demonstrates this exact cliff: at high utilization the market reaches `MathOverflow` inside `scaled_to_original` before the index cap, after which both withdrawal and repayment remain frozen. [3](#0-2) 

This permanently freezes supplier principal and yield and prevents borrowers or liquidators from reducing debt, satisfying the permanent-freezing and insolvency-adjacent impact classes. [14](#0-13) 

### Likelihood Explanation
A single sufficiently funded account can initiate the condition through the public `Controller::supply` and `Controller::borrow` paths by creating a large lending balance and borrowing most of it, provided the market's configured caps admit the size. [15](#0-14) [16](#0-15) 

Interest then accrues passively, and any caller can trigger the fatal transition through the public `update_indexes` entrypoint. [17](#0-16) [10](#0-9) 

The practical barrier is substantial capitalization rather than privileged access: the proof uses an 18-decimal market with a billion whole supplied tokens and 98% utilization. [18](#0-17) 

The protocol documents the same representability boundary: token-to-RAY inputs have an `i128` ceiling, and accrued position values or market totals can overflow before the fixed index ceiling. [19](#0-18) 

### Recommendation
Clamp each index to a market-specific representable ceiling before share valuation, rather than using only the global `1e36` index cap. [8](#0-7) [1](#0-0) 

For example, bound borrow and supply indexes by approximately `i128::MAX / borrowed_shares` and `i128::MAX / supplied_shares`, respectively, or perform the utilization and reward calculations in `I256` and commit only representable results. [20](#0-19) [21](#0-20) 

The overflow check should occur before `scaled_to_original`, and the resulting index should still be committed so that subsequent calls can continue operating below the market-specific bound. [1](#0-0) [22](#0-21) 

### Proof of Concept
The existing regression test supplies one billion whole 18-decimal units, borrows 98% of the market, advances ledger time in a loop, calls `update_indexes`, and observes `MATH_OVERFLOW`. [23](#0-22) 

After the failed accrual, both `withdraw` and `repay` fail with the same error, proving that the trap is not limited to the keeper path. [24](#0-23) 

```rust
// tests/test-harness/tests/controller/large_positions_and_long_horizons.rs
let principal = BILLION * 10i128.pow(18);
t.supply_raw(BOB, "BIG18", principal);
t.borrow_raw(ALICE, "BIG18", principal / 100 * 98);

loop {
    t.advance_time(YEAR_SECS);
    if let Err(e) = t.try_update_indexes_for(&["BIG18"]) {
        break e;
    }
}

assert_contract_error(t.try_withdraw_raw(BOB, "BIG18", 1), errors::MATH_OVERFLOW);
assert_contract_error(t.try_repay(ALICE, "BIG18", 1.0), errors::MATH_OVERFLOW);
```

### Citations

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

**File:** contracts/pool/src/ops/mod.rs (L29-33)
```rust
/// Loads a market cache and accrues interest through the current ledger time.
pub(crate) fn synced_market(env: &Env, hub_asset: &HubAssetKey) -> Cache {
    let mut cache = Cache::load(env, hub_asset);
    interest::global_sync(env, &mut cache);
    cache
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

**File:** common/src/rates/scaling.rs (L12-16)
```rust
/// Converts a scaled `Ray` amount to its original (unscaled) value by
/// multiplying by `index`, rounding half up.
pub fn scaled_to_original(env: &Env, scaled: Ray, index: Ray) -> Ray {
    scaled.mul(env, index)
}
```

**File:** common/src/math/fp.rs (L49-52)
```rust
    /// Multiplies two ray values, rounding the result half up.
    pub fn mul(self, env: &Env, other: Ray) -> Ray {
        Ray(fp_core::mul_div_half_up(env, self.0, other.0, RAY))
    }
```

**File:** common/src/math/fp_core.rs (L1-8)
```rust
//! Raw `i128` arithmetic primitives behind the fixed-point newtypes in
//! [`super::fp`]: overflow-safe `x * y / d` with half-up, floor and ceiling
//! rounding, plus rescaling between decimal precisions.
//!
//! Every multiply-divide first attempts the whole computation in `i128` and
//! only widens the operands to `I256` when the intermediate product does not
//! fit. The widened path is exact, so both paths return the same value.
//! `I256` operations are host calls, so the `i128` path costs less.
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

**File:** contracts/pool/src/ops/market.rs (L65-72)
```rust
pub(crate) fn accrue(env: &Env, hub_assets: Vec<HubAssetKey>) {
    renew_instance(env);

    for hub_asset in hub_assets.iter() {
        let mut cache = Cache::load(env, &hub_asset);
        interest::global_sync(env, &mut cache);
        events::emit_market_state(env, cache.commit());
    }
```

**File:** contracts/pool/src/cache/mod.rs (L133-140)
```rust
    /// Milliseconds between last accrual and the stamped current time.
    pub(crate) fn elapsed_ms(&self) -> u64 {
        self.current_timestamp.saturating_sub(self.last_timestamp)
    }

    /// `true` when interest should be compounded before further mutations.
    pub(crate) fn needs_accrual(&self) -> bool {
        self.elapsed_ms() > 0
```

**File:** contracts/pool/src/lib.rs (L128-180)
```rust
    /// Accrues, mints scaled supply shares and credits cash per entry. The
    /// controller transfers the tokens in before this call. Owner-only.
    #[only_owner]
    fn supply(env: Env, entries: Vec<PoolSupplyEntry>) -> Vec<PoolPositionMutation> {
        ops::run_batch(&env, entries, ops::supply::apply)
    }

    /// Batch-borrows assets and transfers them to `receiver`: accrues
    /// interest, mints scaled debt, debits cash, and enforces max
    /// utilization after each mint. Restricted to the owner; returns one
    /// [`PoolPositionMutation`] per entry.
    #[only_owner]
    fn borrow(
        env: Env,
        receiver: Address,
        entries: Vec<PoolBorrowEntry>,
    ) -> Vec<PoolPositionMutation> {
        ops::run_batch(&env, entries, |env, entry| {
            ops::borrow::apply(env, &receiver, entry)
        })
    }

    /// Burns supply shares and transfers the underlying to `receiver`.
    /// `is_liquidation` skips the max-utilization check and may withhold a
    /// protocol fee. Owner-only; `actual_amount` is gross of that fee.
    #[only_owner]
    fn withdraw(
        env: Env,
        receiver: Address,
        is_liquidation: bool,
        entries: Vec<PoolWithdrawEntry>,
    ) -> Vec<PoolPositionMutation> {
        ops::run_batch(&env, entries, |env, entry| {
            ops::withdraw::apply(env, &receiver, is_liquidation, entry)
        })
    }

    /// Burns scaled debt up to the repay amount, credits cash with the net
    /// repay and refunds overpayment to `payer`. Owner-only.
    #[only_owner]
    fn repay(env: Env, payer: Address, actions: Vec<PoolAction>) -> Vec<PoolPositionMutation> {
        ops::run_batch(&env, actions, |env, action| {
            ops::repay::apply(env, &payer, action)
        })
    }

    /// Accrues interest for each market in `hub_assets` through the current
    /// ledger time. Commits state even with no elapsed time to reserve the write
    /// footprint, and emits its market state event. Restricted to the owner.
    #[only_owner]
    fn update_indexes(env: Env, hub_assets: Vec<HubAssetKey>) {
        ops::market::accrue(&env, hub_assets);
    }
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

**File:** interfaces/controller/src/lib.rs (L15-29)
```rust
    fn supply(
        env: Env,
        caller: Address,
        account_id: u64,
        spoke_id: u32,
        assets: Vec<(HubAssetKey, i128)>,
    ) -> u64;

    fn borrow(
        env: Env,
        caller: Address,
        account_id: u64,
        borrows: Vec<(HubAssetKey, i128)>,
        to: Option<Address>,
    );
```

**File:** interfaces/controller/src/lib.rs (L131-131)
```rust
    fn update_indexes(env: Env, caller: Address, assets: Vec<HubAssetKey>);
```

**File:** docs/reference/formulas.md (L423-437)
```markdown
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
