### Title
Unbounded RAY debt valuation overflows and permanently freezes a market - ([File: common/src/rates/simulate.rs])

### Summary
Accrual converts aggregate debt shares back to RAY-denominated value by multiplying `borrowed` by the current borrow index without a representability guard. [1](#0-0)  The multiplication ultimately calls `mul_div_half_up`, which panics with `MathOverflow` when the exact widened result exceeds `i128`. [2](#0-1) [3](#0-2)  Because every pool mutation loads and synchronizes the market before applying the requested operation, reaching this numeric boundary makes subsequent `update_indexes`, `supply`, `borrow`, `withdraw`, `repay`, liquidation, flash-loan, revenue, and recapitalization paths fail. [4](#0-3) [5](#0-4) 

### Finding Description
`accrue_step` first evaluates `scaled_to_original(borrowed, borrow_index)` and `scaled_to_original(supplied, supply_index)` to calculate utilization. [6](#0-5)  It then updates the borrow index and again multiplies the unchanged `borrowed` share total by both the old and new indexes inside `calculate_supplier_rewards`. [7](#0-6) [8](#0-7)  `scaled_to_original` is a plain `Ray::mul`, so a market whose aggregate `borrowed * index / RAY` exceeds `i128::MAX` aborts before any state update can be committed. [9](#0-8) [2](#0-1)  The widened `I256` path only protects the intermediate product; conversion back to `i128` still returns `None` for an unrepresentable result and raises `MathOverflow`. [10](#0-9) 

The controller exposes `update_indexes(caller, assets)` as a permissionless authenticated entrypoint and forwards the requested hub assets to the owner-only pool method. [11](#0-10) [12](#0-11)  The pool’s mutating operations use `synced_market` or `renewed_market`, both of which execute `interest::global_sync` before the requested accounting transition. [4](#0-3)  `global_sync` invokes `accrue_step` for each elapsed chunk and therefore reaches the overflowing multiplication before it can advance `last_timestamp` or commit indexes. [13](#0-12) [14](#0-13) 

The index ceiling does not prevent this condition because the debt-value product can exceed `i128::MAX` while `borrow_index` remains below `MAX_BORROW_INDEX_RAY`. [15](#0-14) [16](#0-15) 

### Impact Explanation
This is a permanent market-level denial of service under the deployed arithmetic domain: borrowers cannot repay, suppliers cannot withdraw, liquidators cannot seize collateral, and helpers cannot recapitalize or claim revenue for the affected market. [4](#0-3)  The in-repository reproduction confirms that once the boundary is crossed, `withdraw` and `repay` both revert with `MATH_OVERFLOW`. [17](#0-16)  Directly transferring tokens to the pool cannot repair the condition because the failure is in share-index valuation before cash accounting, and the exposed `recapitalize` path also synchronizes first. [18](#0-17)  Consequently, user funds and unclaimed revenue remain locked absent a privileged contract upgrade, which is outside the unprivileged recovery surface.

### Likelihood Explanation
The trigger requires an extremely large admitted market and enough elapsed accrual for the index to make the aggregate RAY value unrepresentable, so it is not reachable in an ordinary small market. [19](#0-18)  Nevertheless, the protocol explicitly admits positions near the RAY numeric domain, and an unprivileged caller can later invoke `update_indexes` once ledger time has advanced. [11](#0-10)  The repository’s horizon test demonstrates the condition with one billion 18-decimal units at 98% utilization and a steep valid rate curve, after which the index ceiling still has not engaged. [20](#0-19)  The required scale and elapsed-time precondition justify Medium rather than High severity.

### Recommendation
Bound index growth by the representable aggregate value instead of allowing accrual to trap: before `scaled_to_original`, derive the maximum safe index for the current `borrowed` and `supplied` share totals and clamp `new_borrow_index` and `new_supply_index` to that bound as well as the configured index ceilings. [21](#0-20)  The bound should use widened arithmetic, for example `max_index = floor(i128::MAX * RAY / shares)`, so the implementation does not introduce another overflow while calculating the limit. [22](#0-21)  Alternatively, keep aggregate debt and supply valuation in `I256` throughout accrual and only commit values proven to fit `i128`, while explicitly stopping interest at the representable boundary. [23](#0-22)  Add regression coverage showing that `update_indexes`, `repay`, `withdraw`, liquidation, `claim_revenue`, and `recapitalize` remain executable after a market reaches the numeric ceiling. [17](#0-16) 

### Proof of Concept
1. Configure an admitted 18-decimal market with sufficiently large caps, supply `1_000_000_000 * 10^18` base units, supply collateral to the same account, and borrow `980_000_000 * 10^18` base units. [24](#0-23) 
2. Let ledger time advance until `borrowed * borrow_index / RAY` exceeds `i128::MAX`; the existing test advances yearly and calls `update_indexes` until the call fails. [25](#0-24) 
3. The next `update_indexes(caller, [hub_asset])` invokes pool accrual, reaches `scaled_to_original`, and reverts with `MathOverflow`. [12](#0-11) [6](#0-5) 
4. `withdraw` and `repay` subsequently revert for the same reason because both pool paths synchronize the market before burning shares or crediting repayment. [4](#0-3) [26](#0-25)

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

**File:** common/src/math/fp.rs (L49-52)
```rust
    /// Multiplies two ray values, rounding the result half up.
    pub fn mul(self, env: &Env, other: Ray) -> Ray {
        Ray(fp_core::mul_div_half_up(env, self.0, other.0, RAY))
    }
```

**File:** common/src/math/fp_core.rs (L14-20)
```rust
/// Widens `x`, `y`, and `d` to `I256` for overflow-safe intermediate arithmetic.
fn to_i256_operands(env: &Env, x: i128, y: i128, d: i128) -> (I256, I256, I256) {
    (
        I256::from_i128(env, x),
        I256::from_i128(env, y),
        I256::from_i128(env, d),
    )
```

**File:** common/src/math/fp_core.rs (L108-118)
```rust
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

**File:** common/src/math/fp_core.rs (L128-143)
```rust
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

**File:** common/src/rates/index.rs (L13-18)
```rust
pub fn update_borrow_index(env: &Env, old_index: Ray, interest_factor: Ray) -> Ray {
    let new_index = old_index.mul(env, interest_factor);
    if new_index.raw() > MAX_BORROW_INDEX_RAY {
        return Ray::from(MAX_BORROW_INDEX_RAY);
    }
    new_index
```

**File:** common/src/rates/index.rs (L80-84)
```rust
    let old_total_debt = borrowed.mul(env, old_borrow_index);
    let new_total_debt = borrowed.mul(env, new_borrow_index);

    let accrued_interest = new_total_debt.checked_sub(env, old_total_debt);

```

**File:** common/src/rates/scaling.rs (L12-16)
```rust
/// Converts a scaled `Ray` amount to its original (unscaled) value by
/// multiplying by `index`, rounding half up.
pub fn scaled_to_original(env: &Env, scaled: Ray, index: Ray) -> Ray {
    scaled.mul(env, index)
}
```

**File:** contracts/controller/src/lib.rs (L367-372)
```rust
    /// Accrues pool borrow and supply indexes for `assets`. Permissionless;
    /// requires caller authorization.
    #[when_not_paused]
    fn update_indexes(env: Env, caller: Address, assets: Vec<HubAssetKey>) {
        markets::update_indexes(&env, caller, assets);
    }
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

**File:** contracts/pool/src/ops/recapitalize.rs (L44-58)
```rust
pub(crate) fn accounting(
    env: &Env,
    hub_asset: HubAssetKey,
    amount: i128,
) -> RecapitalizationOutcome {
    require_nonneg_amount(env, amount);
    let mut cache = ops::renewed_market(env, &hub_asset);

    let applied = amount.min(guards::backing_shortfall(&cache));
    let refund = amount
        .checked_sub(applied)
        .unwrap_or_else(|| panic_with_error!(env, GenericError::MathOverflow));

    cache.credit_cash(applied);
    cache.commit();
```
