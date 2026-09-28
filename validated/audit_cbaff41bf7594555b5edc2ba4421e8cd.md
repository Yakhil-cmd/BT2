### Title
Market accrual arithmetic can permanently freeze an oversized market - (File: `common/src/rates/simulate.rs`)

### Summary
A market whose scaled debt multiplied by its borrow index exceeds `i128::MAX` can reach a state where every mutation of that market reverts during mandatory accrual. Because the overflow occurs before the market’s state is advanced, no subsequent `update_indexes`, `borrow`, `repay`, `withdraw`, `liquidate`, `flash_loan`, `claim_revenue`, or `recapitalize` call touching that market can recover it. [1](#0-0) [2](#0-1) [3](#0-2) 

### Finding Description
Controller `update_indexes` is permissionless apart from caller authorization and forwards the requested `HubAssetKey` list to the pool. [4](#0-3) [5](#0-4)  The pool loads each market through `synced_market`, which invokes `interest::global_sync` before any operation-specific repayment, withdrawal, or mutation logic runs. [3](#0-2) 

Each accrual chunk first reconstructs total debt and supply by multiplying scaled `borrowed` and `supplied` shares by the current indexes. [6](#0-5)  `scaled_to_original` performs a checked fixed-point multiplication and panics when the RAY-scaled product exceeds `i128`. [7](#0-6) 

The borrow-index cap does not prevent this condition: the stale index is multiplied by total scaled debt before the new index or its cap can be applied, so a market can cross the value ceiling while `borrow_index < MAX_BORROW_INDEX_RAY`. [8](#0-7)  The repository’s deterministic test demonstrates the condition: after a one-billion-unit, 18-decimal market remains at 98% utilization for enough yearly accrual periods, `update_indexes` fails with `MathOverflow`, followed by identical failures for `withdraw` and `repay`. [9](#0-8) 

### Impact Explanation
This is permanent freezing of user funds and market functionality. Suppliers cannot withdraw, borrowers cannot repay, liquidators cannot reduce the position, revenue cannot be claimed, flash loans cannot settle, and recapitalization cannot repair the market because all of those paths synchronize the market first. [3](#0-2) [10](#0-9) 

The market-level share book is shared across users. Consequently, one sufficiently large debt book can freeze funds belonging to every supplier and borrower in that `(hub, token)` market, not merely the account that created the oversized debt. [11](#0-10) [1](#0-0) 

### Likelihood Explanation
An unprivileged account can reach the setup through ordinary `supply` and `borrow` calls when governance-configured supply caps, borrow caps, collateral value, and utilization parameters permit the required book size. [12](#0-11)  The attacker does not need privileged calls to trigger the terminal condition: permissionless `update_indexes` executes the accrual after enough ledger time elapses. [4](#0-3) [2](#0-1) 

Likelihood is constrained by the need for an extremely large market and sustained high utilization; the checked domain ceiling is `i128::MAX`, and the demonstrated borrow index remains below the configured index cap when the value product overflows. [13](#0-12) [14](#0-13)  Nevertheless, the panic is deterministic once that state is reached and there is no permissionless or administrative escape path because even parameter updates and recapitalization call the same accrual path. [15](#0-14) [16](#0-15) 

### Recommendation
Do not reconstruct total debt with fallible `i128` multiplication on every accrual. Compute utilization and accrued interest with a widened or saturating representation that preserves ordering while avoiding storage-value overflow, or split the scaled debt and index multiplication so an oversized intermediate cannot permanently poison accrual.

At minimum:

- make `accrue_step` handle `scaled * index > i128::MAX` without reverting;
- advance `last_timestamp` safely when the mathematical value exceeds the representable domain;
- enforce market-level scaled-value ceilings below the accrual overflow threshold rather than only asset-decimal caps;
- add a production regression equivalent to `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` asserting that `update_indexes`, `repay`, `withdraw`, and liquidation remain executable. [1](#0-0) [13](#0-12) [17](#0-16) 

### Proof of Concept
The existing deterministic test supplies one billion whole units of an 18-decimal asset, borrows 98% of it, advances the ledger in yearly intervals, and invokes permissionless index updates until accrual reverts. [18](#0-17)  It then asserts `MathOverflow`, verifies `borrow_index < MAX_BORROW_INDEX_RAY`, and shows both withdrawal and repayment fail on the same accrual. [19](#0-18) 

Equivalent user-facing sequence:

1. Supplier calls `supply(caller, account_id, spoke_id, [(hub_asset, amount)])` to place a cap-compliant very large amount in the market. [20](#0-19) 
2. A sufficiently collateralized borrower calls `borrow(caller, account_id, [(hub_asset, amount)], None)` to leave sustained high utilization. [21](#0-20) 
3. Any address calls `update_indexes(caller, [hub_asset])` after enough elapsed ledger time. [4](#0-3) 
4. `global_sync` calls `accrue_step`; `borrowed.mul(borrow_index)` exceeds `i128::MAX` and reverts before `last_timestamp` is updated. [2](#0-1) [8](#0-7) 
5. Because the same `synced_market` prelude runs before market mutations, subsequent repayments, withdrawals, liquidations, flash loans, revenue claims, and recapitalization attempts revert identically. [3](#0-2)

### Citations

**File:** common/src/rates/simulate.rs (L51-69)
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

**File:** contracts/controller/src/lib.rs (L367-372)
```rust
    /// Accrues pool borrow and supply indexes for `assets`. Permissionless;
    /// requires caller authorization.
    #[when_not_paused]
    fn update_indexes(env: Env, caller: Address, assets: Vec<HubAssetKey>) {
        markets::update_indexes(&env, caller, assets);
    }
```

**File:** contracts/controller/src/markets.rs (L87-100)
```rust
/// Accrues indexes under the current model before replacing rate and flash-loan
/// parameters, then emits the new configuration.
pub(crate) fn upgrade_liquidity_pool_params(
    env: &Env,
    hub_asset: &HubAssetKey,
    params: &InterestRateModel,
) {
    let mut cache = Context::new(env);

    let pool_addr = cache.cached_pool_address();

    pool_update_indexes_call(env, &pool_addr, &vec![env, hub_asset.clone()]);

    pool_update_params_call(env, &pool_addr, hub_asset, params);
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

**File:** contracts/controller/src/markets.rs (L142-164)
```rust
pub(crate) fn recapitalize(
    env: &Env,
    payer: Address,
    hub_asset: HubAssetKey,
    amount: i128,
) -> i128 {
    validation::require_authorized_caller(env, &payer);
    require_positive_amount(env, amount);

    let mut cache = Context::new(env);
    let pool_addr = cache.cached_pool_address();
    // Prefund the pool and credit only its measured receipt.
    let received = payments::transfer_amount_measured(
        env,
        &hub_asset.asset,
        &payer,
        &pool_addr,
        amount,
        GenericError::AmountMustBePositive,
    );

    pool_recapitalize_call(env, &pool_addr, &hub_asset, &payer, received).actual_amount
}
```

**File:** common/src/rates/scaling.rs (L12-16)
```rust
/// Converts a scaled `Ray` amount to its original (unscaled) value by
/// multiplying by `index`, rounding half up.
pub fn scaled_to_original(env: &Env, scaled: Ray, index: Ray) -> Ray {
    scaled.mul(env, index)
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

**File:** contracts/pool/README.md (L180-184)
```markdown
```text
supplied, borrowed, revenue : Ray, scaled shares
borrow_index                : Ray, monotone non-decreasing
supply_index                : Ray, grows on interest, falls on bad debt
cash                        : i128, token-native, bookkeeping
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
