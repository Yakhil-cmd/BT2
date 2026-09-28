### Title
RAY index accrual overflows scaled market value and permanently freezes repayments, withdrawals, and liquidations - (File: `common/src/rates/simulate.rs`)

### Summary
Interest accrual converts total scaled borrow and supply into unscaled RAY values before calculating utilization. When `scaled_amount * index / RAY` exceeds `i128::MAX`, `Ray::mul` panics with `MathOverflow` before the borrow-index ceiling can take effect. Because every market mutation performs accrual first, a sufficiently large, highly utilized market becomes permanently unusable: `update_indexes`, `repay`, `withdraw`, `liquidate`, and other paths touching that market all revert. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

### Finding Description
`accrue_step` starts by calculating `borrowed_original` and `supplied_original` through `scaled_to_original`. [5](#0-4)  `scaled_to_original` is a `Ray::mul`, which computes `scaled * index / RAY` through `mul_div_half_up`. [2](#0-1) [6](#0-5)  `mul_div_half_up` panics with `GenericError::MathOverflow` when the exact quotient cannot be represented as an `i128`. [7](#0-6) 

The same unscaled debt multiplication is also repeated when calculating supplier rewards: `calculate_supplier_rewards` computes both `borrowed * old_borrow_index` and `borrowed * new_borrow_index`. [8](#0-7)  The borrow index is nominally capped at `MAX_BORROW_INDEX_RAY`, but the cap is applied only after computing the index and does not bound the total scaled-debt product to `i128::MAX`. [9](#0-8) 

The permissionless controller `update_indexes` path calls `markets::update_indexes`, which forwards the selected assets to the pool's `update_indexes` entrypoint. [10](#0-9) [11](#0-10)  Pool accrual repeatedly executes `accrue_step` through `global_sync`. [12](#0-11)  Once the accrual panics, the transaction reverts without persisting a terminal error state or bypass flag, so the next attempt recomputes the same overflowing product. [13](#0-12) 

The repository has a direct regression test demonstrating the cliff: a one-billion-whole-token, 18-decimal market at 98% utilization eventually returns `MATH_OVERFLOW`, while its borrow index remains below `MAX_BORROW_INDEX_RAY`. [14](#0-13)  The same test verifies that subsequent withdrawal and repayment calls fail with `MATH_OVERFLOW`. [15](#0-14) 

### Impact Explanation
All user funds in the affected market can be permanently frozen: suppliers cannot withdraw, borrowers cannot repay or unwind collateral, and liquidators cannot run the accrual-dependent liquidation path. [4](#0-3) [16](#0-15) [17](#0-16) 

This is not a transient revert that a smaller amount or another caller can avoid, because the panic depends on market-wide scaled totals and accrued indexes rather than on the submitted withdrawal or repayment amount. [18](#0-17) [19](#0-18)  The failed state also cannot be repaired by ordinary `recapitalize`, supply, or cleanup calls because those operations load and synchronize the same market accounting path. [12](#0-11) 

### Likelihood Explanation
Triggering the condition requires an unusually large market and an index around the documented RAY-value boundary, so exploitation is economically difficult rather than a normal-size rounding attack. [20](#0-19)  The tested configuration uses a one-billion-whole-token 18-decimal market, approximately 98% utilization, and long-term high-utilization accrual. [21](#0-20) 

Nevertheless, the trigger uses ordinary unprivileged controller operations: supplying collateral, borrowing the target asset, waiting for interest to accrue, and calling the permissionless `update_indexes` entrypoint. [22](#0-21) [10](#0-9)  The impacted code explicitly documents that caps and bounded indexes do not guarantee that future accrued values fit the RAY domain, and that repayment or withdrawal can be blocked once value overflow occurs. [23](#0-22) 

### Recommendation
Accrual should not panic merely because the product of market-wide scaled balances and an index exceeds the `i128` RAY domain. At minimum, detect the value-overflow boundary before updating indexes and enter an explicit halted state that still permits conservative closes, repayments, withdrawals, liquidation, or recapitalization. A stronger fix is to represent market totals and utilization calculations with widened arithmetic throughout accrual, or store/advance state in a representation that cannot require an unrepresentable `i128` intermediate. [24](#0-23) [25](#0-24) 

The fix must also ensure the borrow-index ceiling is enforced before any unrepresentable total-value multiplication can abort the transaction. [9](#0-8) [26](#0-25) 

### Proof of Concept
A concrete flow for a deployed market with an adequate configured cap is:

```text
let target = HubAssetKey { hub_id: H, asset: BIG18_TOKEN };
let collateral = HubAssetKey { hub_id: H, asset: COLLATERAL_TOKEN };

let principal: i128 = 1_000_000_000 * 10^18;
let debt: i128 = principal * 98 / 100;

controller.supply(
    attacker,
    supplier_account_id,
    spoke_id,
    vec![(target, principal)],
);

controller.supply(
    attacker,
    borrower_account_id,
    spoke_id,
    vec![(collateral, sufficient_collateral)],
);

controller.borrow(
    attacker,
    borrower_account_id,
    vec![(target, debt)],
    Some(attacker),
);

// Advance ledger time repeatedly at sustained ~98% utilization.
controller.update_indexes(attacker, vec![target]);
```

Eventually `update_indexes` reaches `accrue_step`, which evaluates `borrowed * borrow_index` and `supplied * supply_index`; one of these exact products exceeds `i128::MAX` and panics with `MathOverflow`. [18](#0-17) [2](#0-1) 

The existing test demonstrates the same boundary with `principal = BILLION * 10^18`, `debt = principal * 98 / 100`, repeated yearly `update_indexes`, and a resulting `MATH_OVERFLOW` before `MAX_BORROW_INDEX_RAY`. [14](#0-13)  It then verifies that both a withdrawal and a repayment revert with `MATH_OVERFLOW`, establishing the permanent market freeze. [15](#0-14)

### Citations

**File:** common/src/rates/simulate.rs (L51-80)
```rust
pub fn accrue_step(
    env: &Env,
    params: &MarketParams,
    borrowed: Ray,
    supplied: Ray,
    borrow_index: Ray,
    supply_index: Ray,
    delta_ms: u64,
) -> AccrualStep {
    let borrowed_original = scaled_to_original(env, borrowed, borrow_index);
    let supplied_original = scaled_to_original(env, supplied, supply_index);
    let util = utilization(env, borrowed_original, supplied_original);
    let borrow_rate = calculate_borrow_rate(env, util, params);
    let interest_factor = compound_interest(env, borrow_rate, delta_ms);

    let new_borrow_index = update_borrow_index(env, borrow_index, interest_factor);

    let (supplier_rewards, protocol_fee) =
        calculate_supplier_rewards(env, params, borrowed, new_borrow_index, borrow_index);

    let new_supply_index = update_supply_index(env, supplied, supply_index, supplier_rewards);
    let supplier_shortfall = supply_index_reward_shortfall(
        env,
        supplied,
        supply_index,
        new_supply_index,
        supplier_rewards,
    );

    let protocol_reward = protocol_fee.checked_add(env, supplier_shortfall);
```

**File:** common/src/rates/scaling.rs (L12-16)
```rust
/// Converts a scaled `Ray` amount to its original (unscaled) value by
/// multiplying by `index`, rounding half up.
pub fn scaled_to_original(env: &Env, scaled: Ray, index: Ray) -> Ray {
    scaled.mul(env, index)
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

**File:** tests/test-harness/tests/controller/large_positions_and_long_horizons.rs (L315-319)
```rust
/// The cliff. A billion whole tokens is `1e36` raw ray; the value ceiling is
/// `i128::MAX`, 170 times that. At the XLM curve's steep segment the index
/// grows past 170x in a few years, and the next accrual panics inside
/// `scaled_to_original`. Every verb accrues first, so the market freezes:
/// no repay, no withdraw, no liquidation. The index cap never engages.
```

**File:** tests/test-harness/tests/controller/large_positions_and_long_horizons.rs (L321-353)
```rust
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
```

**File:** tests/test-harness/tests/controller/large_positions_and_long_horizons.rs (L354-356)
```rust
    // The market is frozen: exits and repayments accrue first and hit the same panic.
    assert_contract_error(t.try_withdraw_raw(BOB, "BIG18", 1), errors::MATH_OVERFLOW);
    assert_contract_error(t.try_repay(ALICE, "BIG18", 1.0), errors::MATH_OVERFLOW);
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

**File:** common/src/math/fp_core.rs (L138-143)
```rust
    let (x256, y256, d256) = to_i256_operands(env, x, y, d);
    x256.mul(&y256)
        .add(&I256::from_i128(env, half))
        .div(&d256)
        .to_i128()
}
```

**File:** contracts/controller/src/lib.rs (L90-114)
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
```

**File:** contracts/controller/src/lib.rs (L367-371)
```rust
    /// Accrues pool borrow and supply indexes for `assets`. Permissionless;
    /// requires caller authorization.
    #[when_not_paused]
    fn update_indexes(env: Env, caller: Address, assets: Vec<HubAssetKey>) {
        markets::update_indexes(&env, caller, assets);
```

**File:** contracts/controller/src/markets.rs (L118-125)
```rust
/// Accrues indexes for each hub asset. Requires caller authorization and no flash loan.
pub(crate) fn update_indexes(env: &Env, caller: Address, assets: Vec<HubAssetKey>) {
    validation::require_authorized_caller(env, &caller);

    let mut cache = Context::new(env);
    let pool_addr = cache.cached_pool_address();
    pool_update_indexes_call(env, &pool_addr, &assets);
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

**File:** contracts/pool/src/ops/withdraw.rs (L57-64)
```rust
pub(crate) fn accounting(
    env: &Env,
    is_liquidation: bool,
    entry: &PoolWithdrawEntry,
) -> WithdrawOutcome {
    require_nonneg_amount(env, entry.protocol_fee);
    let (mut cache, position) = ops::load_leg(env, &entry.action);

```

**File:** contracts/pool/src/ops/repay.rs (L36-45)
```rust
/// Accrues interest, resolves the repay amount into burned debt shares and
/// overpayment, burns the shares, and credits the net repay to cash without
/// transferring the overpayment refund. Panics if a positive net repay would
/// burn zero scaled shares.
pub(crate) fn accounting(env: &Env, action: &PoolAction) -> RepayOutcome {
    let (mut cache, position) = ops::load_leg(env, action);
    let amount = action.amount;

    let (burned, overpayment) = cache.resolve_repay(amount, position);
    let net_repay = amount
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
