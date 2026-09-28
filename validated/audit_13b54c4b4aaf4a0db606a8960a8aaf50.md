### Title

Interest accrual overflows before the borrow-index cap and permanently freezes a large market - ([File: common/src/rates/simulate.rs](common/src/rates/simulate.rs))

### Summary

`accrue_step` computes `borrowed * borrow_index` before the configured `MAX_BORROW_INDEX_RAY` cap can protect the market. If scaled debt exceeds approximately `i128::MAX / (borrow_index / RAY)`, every state-changing market operation panics during mandatory synchronization, permanently freezing repayment, withdrawal, liquidation, bad-debt cleanup, and recapitalization.

### Finding Description

Every pool operation calls `synced_market`, which invokes `interest::global_sync` before applying the operation. [1](#0-0)  `global_sync` passes the market’s aggregate scaled debt and borrow index into `accrue_step`. [2](#0-1) 

`accrue_step` first evaluates `scaled_to_original(borrowed, borrow_index)`, implemented as the checked half-up product `borrowed * borrow_index / RAY`. [3](#0-2) [4](#0-3)  The resulting `MathOverflow` occurs before `update_borrow_index` is reached and before its index ceiling can clamp future growth. [5](#0-4) 

For example, an 18-decimal deposit of 1 billion whole tokens produces approximately `10^36` scaled units; a borrow book at 98% of that amount reaches the `i128::MAX` valuation boundary when the borrow index reaches roughly 170× RAY, while the configured index ceiling is `10^9`× RAY. [6](#0-5)  The repository’s integration test demonstrates that once this happens, `update_indexes`, `withdraw`, and `repay` all fail with `MathOverflow`. [7](#0-6) 

### Impact Explanation

This permanently freezes all user funds and debt in the affected hub-asset market because every relevant pool action loads an interest-synced cache before it can mutate state. [8](#0-7) 

The attacker-facing path is ordinary controller usage: create an account with `supply`, borrow against it with `borrow`, and later let time advance; any subsequent unprivileged `update_indexes` call triggers the overflow. [9](#0-8) [10](#0-9) 

### Likelihood Explanation

Likelihood is low-to-medium: the condition requires a very large real token balance, configured caps high enough to admit it, and sustained high-utilization accrual. However, the required 18-decimal amount is within the protocol’s own cap domain, which permits up to `i128::MAX / 10^(27-decimals)` base units. [11](#0-10) 

Once aggregate market debt reaches the numeric boundary, no special privileges are needed to trigger the freeze; `update_indexes` only requires an authorized caller signature and forwards the selected assets to the pool. [10](#0-9) 

### Recommendation

Check `borrowed * borrow_index` with a saturating or explicit bounded-value helper before converting debt to original units, and enforce a market-level scaled-debt ceiling derived from `MAX_BORROW_INDEX_RAY` and `i128::MAX`. Alternatively, make accrual skip interest once the debt value boundary is reached, while still committing the updated timestamp, so `repay`, `withdraw`, liquidation, and bad-debt cleanup remain executable.

### Proof of Concept

1. Configure an 18-decimal borrowable market with near-maximum caps and a steep rate curve, plus a separate collateral market.
2. Call `controller.supply(caller, 0, spoke_id, [(BIG18, 1_000_000_000 * 10^18)])`.
3. Supply sufficient collateral to the same account and call `controller.borrow(caller, account_id, [(BIG18, 980_000_000 * 10^18)], None)`.
4. Advance ledger time until `borrow_index` approaches approximately `170 * RAY`.
5. Call `controller.update_indexes(caller, [BIG18])`.
6. `accrue_step` panics in `scaled_to_original`; subsequent `repay`, `withdraw`, `liquidate`, `clean_bad_debt`, and `recapitalize` attempts panic during `global_sync` before their own logic executes. [12](#0-11)

### Citations

**File:** contracts/pool/src/ops/mod.rs (L29-33)
```rust
/// Loads a market cache and accrues interest through the current ledger time.
pub(crate) fn synced_market(env: &Env, hub_asset: &HubAssetKey) -> Cache {
    let mut cache = Cache::load(env, hub_asset);
    interest::global_sync(env, &mut cache);
    cache
```

**File:** contracts/pool/src/ops/mod.rs (L42-47)
```rust
/// Validates `action.amount ≥ 0`, syncs the market, and returns (cache, scaled position).
pub(crate) fn load_leg(env: &Env, action: &PoolAction) -> (Cache, Ray) {
    require_nonneg_amount(env, action.amount);
    let cache = synced_market(env, &action.hub_asset);
    (cache, Ray::from(action.position.scaled_amount))
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

**File:** common/src/rates/simulate.rs (L51-61)
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
```

**File:** common/src/rates/scaling.rs (L12-16)
```rust
/// Converts a scaled `Ray` amount to its original (unscaled) value by
/// multiplying by `index`, rounding half up.
pub fn scaled_to_original(env: &Env, scaled: Ray, index: Ray) -> Ray {
    scaled.mul(env, index)
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

**File:** common/src/validation.rs (L41-56)
```rust
/// Returns the largest cap, in asset base units, whose ray-scaled form still
/// fits in `i128`.
///
/// Returns 0 when `asset_decimals > RAY_DECIMALS`, since the ray form is not
/// representable in that case. Enforced by
/// [`require_cap_within_asset_domain`], so stored caps can never overflow the
/// asset→ray rescale.
pub fn max_cap_for_decimals(asset_decimals: u32) -> i128 {
    let Some(exp) = RAY_DECIMALS.checked_sub(asset_decimals) else {
        return 0;
    };
    let upscale = 10i128
        .checked_pow(exp)
        .expect("10^(RAY_DECIMALS - asset_decimals) fits i128 for asset_decimals <= RAY_DECIMALS");
    i128::MAX / upscale
}
```
