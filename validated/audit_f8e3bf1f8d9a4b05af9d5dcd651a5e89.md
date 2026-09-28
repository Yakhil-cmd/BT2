### Title
Permanent market freeze from scaled-position value overflow during interest accrual - (File: `common/src/rates/simulate.rs`)

### Summary
`accrue_step` converts aggregate scaled borrow and supply shares into RAY-denominated values before calculating utilization, and the conversion panics when `scaled * index / RAY` no longer fits in `i128`. A sufficiently large admitted market can therefore cross the representable-value boundary while its borrow index remains below `MAX_BORROW_INDEX_RAY`, permanently preventing every market operation that syncs interest. [1](#0-0) [2](#0-1) [3](#0-2) 

### Finding Description
`scaled_to_original` delegates to `Ray::mul`, which computes `scaled * index / RAY` rounded half-up. [2](#0-1) [4](#0-3)  The arithmetic can use an `I256` intermediate, but the final value must fit `i128`; otherwise `to_i128` returns `None` and the helper raises `MathOverflow`. [5](#0-4) [6](#0-5) 

The accrual path performs this conversion for both total borrowed and total supplied shares on every chunk, before deriving utilization and the next borrow index. [1](#0-0)  `update_indexes(caller, assets)` is permissionless apart from caller authorization and forwards the requested `HubAssetKey` vector to the pool. [7](#0-6) [8](#0-7)  The pool's `update_indexes` entrypoint loads each market and calls `global_sync`, and the shared operation loader performs the same synchronization before repayments, withdrawals, borrows, liquidations, and other market mutations. [9](#0-8) [10](#0-9) 

The repository's own regression test demonstrates the boundary: one billion whole units of an 18-decimal asset create a RAY value near `1e36`, while `i128::MAX` is only about 170 times larger, so index growth below the `10^9 × RAY` index cap can make the next accrual revert. [11](#0-10)  After that point, the test confirms that withdrawal and repayment fail with the same `MathOverflow`. [12](#0-11) 

### Impact Explanation
All user funds in the affected `(hub_id, asset)` market become permanently frozen because exit and debt-clearing operations must synchronize the market before changing state. [10](#0-9)  Suppliers cannot withdraw, borrowers cannot repay, and liquidators cannot operate on the frozen market because each path reaches `global_sync` and then `scaled_to_original`. [13](#0-12) [14](#0-13) [15](#0-14) 

### Likelihood Explanation
The trigger requires a very large admitted position and enough index growth for `scaled * index / RAY` to exceed `i128::MAX`, but it requires no privileged call once a suitably configured market exists. [1](#0-0) [7](#0-6)  The concrete test fixture uses an 18-decimal market, a billion-token deposit, approximately 98% utilization, and repeated accrual until the first `update_indexes` failure. [16](#0-15)  This is a Medium-likelihood, permanent-freeze issue because the economic prerequisites are substantial and depend on listing caps, token supply, collateralization, and the configured rate curve, but the resulting state transition is deterministic once those bounds admit the position. [17](#0-16) 

### Recommendation
Add an explicit representable-value bound to index accrual rather than allowing the first conversion to panic. For example, cap each market's borrow and supply indexes at the largest values for which `borrowed * borrow_index / RAY` and `supplied * supply_index / RAY` remain representable, and derive that cap before applying `interest_factor`. [18](#0-17) [19](#0-18)  The utilization calculation should also avoid materializing both aggregate values where a widened rational comparison or dynamically bounded calculation can preserve behavior without an unrecoverable `MathOverflow`. [1](#0-0) 

### Proof of Concept
The existing regression in `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs` provides a direct reproduction:

```rust
let principal = 1_000_000_000i128 * 10i128.pow(18); // 1e27 base units, 18 decimals
t.supply_raw(BOB, "BIG18", principal);

let debt = principal / 100 * 98;
t.supply_raw(ALICE, "COL", 1_000_000_000i128 * 10_000_000 * 3);
t.borrow_raw(ALICE, "BIG18", debt);

loop {
    t.advance_time(31_556_926); // one year
    if t.try_update_indexes_for(&["BIG18"]).is_err() {
        break;
    }
}

assert_contract_error(t.try_withdraw_raw(BOB, "BIG18", 1), errors::MATH_OVERFLOW);
assert_contract_error(t.try_repay(ALICE, "BIG18", 1.0), errors::MATH_OVERFLOW);
```

The public analogue is `Controller::supply(caller, 0, spoke_id, assets)`, `Controller::borrow(caller, account_id, [(BIG18, debt)], None)`, followed by permissionless `Controller::update_indexes(caller, [BIG18])` after ledger time advances. [20](#0-19) [7](#0-6)  The tested transaction reverts inside `accrue_step` while evaluating aggregate scaled value, leaving `borrow_index` below `MAX_BORROW_INDEX_RAY` and causing subsequent withdrawals and repayments to fail at the same synchronization point. [1](#0-0) [12](#0-11)

### Citations

**File:** common/src/rates/simulate.rs (L60-66)
```rust
    let borrowed_original = scaled_to_original(env, borrowed, borrow_index);
    let supplied_original = scaled_to_original(env, supplied, supply_index);
    let util = utilization(env, borrowed_original, supplied_original);
    let borrow_rate = calculate_borrow_rate(env, util, params);
    let interest_factor = compound_interest(env, borrow_rate, delta_ms);

    let new_borrow_index = update_borrow_index(env, borrow_index, interest_factor);
```

**File:** common/src/rates/scaling.rs (L12-16)
```rust
/// Converts a scaled `Ray` amount to its original (unscaled) value by
/// multiplying by `index`, rounding half up.
pub fn scaled_to_original(env: &Env, scaled: Ray, index: Ray) -> Ray {
    scaled.mul(env, index)
}
```

**File:** contracts/pool/src/ops/mod.rs (L29-46)
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

/// Validates `action.amount ≥ 0`, syncs the market, and returns (cache, scaled position).
pub(crate) fn load_leg(env: &Env, action: &PoolAction) -> (Cache, Ray) {
    require_nonneg_amount(env, action.amount);
    let cache = synced_market(env, &action.hub_asset);
    (cache, Ray::from(action.position.scaled_amount))
```

**File:** common/src/math/fp.rs (L49-52)
```rust
    /// Multiplies two ray values, rounding the result half up.
    pub fn mul(self, env: &Env, other: Ray) -> Ray {
        Ray(fp_core::mul_div_half_up(env, self.0, other.0, RAY))
    }
```

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

**File:** common/src/math/fp_core.rs (L298-303)
```rust
/// Converts an `I256` to `i128`, panicking with `GenericError::MathOverflow` if it does not
/// fit.
fn to_i128(env: &Env, val: &I256) -> i128 {
    val.to_i128()
        .unwrap_or_else(|| panic_with_error!(env, GenericError::MathOverflow))
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

**File:** contracts/controller/src/lib.rs (L367-371)
```rust
    /// Accrues pool borrow and supply indexes for `assets`. Permissionless;
    /// requires caller authorization.
    #[when_not_paused]
    fn update_indexes(env: Env, caller: Address, assets: Vec<HubAssetKey>) {
        markets::update_indexes(&env, caller, assets);
```

**File:** contracts/controller/src/markets.rs (L118-124)
```rust
/// Accrues indexes for each hub asset. Requires caller authorization and no flash loan.
pub(crate) fn update_indexes(env: &Env, caller: Address, assets: Vec<HubAssetKey>) {
    validation::require_authorized_caller(env, &caller);

    let mut cache = Context::new(env);
    let pool_addr = cache.cached_pool_address();
    pool_update_indexes_call(env, &pool_addr, &assets);
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

**File:** contracts/pool/src/ops/repay.rs (L40-45)
```rust
pub(crate) fn accounting(env: &Env, action: &PoolAction) -> RepayOutcome {
    let (mut cache, position) = ops::load_leg(env, action);
    let amount = action.amount;

    let (burned, overpayment) = cache.resolve_repay(amount, position);
    let net_repay = amount
```

**File:** contracts/pool/src/ops/withdraw.rs (L62-67)
```rust
    require_nonneg_amount(env, entry.protocol_fee);
    let (mut cache, position) = ops::load_leg(env, &entry.action);

    let (burned, gross_amount) = resolve_close_or_partial(&cache, entry.action.amount, position);
    // Burn first: `protocol_fee_shares` caps the fee mint at `i128::MAX - supplied`.
    let remaining = burn_position(env, &mut cache, position, burned);
```

**File:** contracts/pool/src/interest.rs (L20-30)
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
```

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
