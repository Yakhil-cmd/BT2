### Title
Accrued market value overflows before index caps and permanently freezes market operations - (File: common/src/rates/scaling.rs)

### Summary

A very large, highly utilized market can reach a state where converting scaled supply or debt into its accrued RAY value overflows `i128`. Every pool mutation synchronizes interest before applying the requested operation, so once this boundary is crossed, `update_indexes`, `repay`, `withdraw`, `liquidate`, `flash_loan`, `clean_bad_debt`, and other controller paths touching the market all revert. The configured `MAX_BORROW_INDEX_RAY` does not prevent this because the value can exceed `i128::MAX` while the index remains below that ceiling.

### Finding Description

The core accrual step derives utilization by unscaling both market totals: `borrowed * borrow_index` and `supplied * supply_index`. Both use `scaled_to_original`, which calls `Ray::mul` and rejects any result outside `i128` with `MathOverflow`. [1](#0-0) [2](#0-1) [3](#0-2) 

The pool applies this synchronization before market mutations through `synced_market` and `global_sync`, and `update_indexes` performs the same accrual directly. [4](#0-3) [5](#0-4) [6](#0-5) 

The controller exposes this path through permissionless `update_indexes`, while `supply`, `borrow`, `withdraw`, `repay`, `liquidate`, `clean_bad_debt`, `flash_loan`, `claim_revenue`, and `recapitalize` also reach pool operations that synchronize the market first. [7](#0-6) [8](#0-7) 

A production-shaped test demonstrates the failure: a 1-billion-token, 18-decimal market borrowed to 98% utilization eventually causes `update_indexes` to return `MathOverflow`, after which even a one-unit withdrawal and a minimal repayment fail for the same reason. [9](#0-8) 

### Impact Explanation

This permanently freezes all assets associated with the affected market. Suppliers cannot withdraw, borrowers cannot repay, liquidators cannot liquidate distressed accounts, bad-debt cleanup cannot run, flash loans cannot execute, and revenue cannot be claimed. The market’s remaining pool cash is therefore inaccessible even though the underlying ledger entries still exist.

The failure is permanent because no operation can first reduce the oversized scaled supply or debt: every path that could reduce either value reverts during the preliminary accrual. Permissionless `recapitalize` also cannot rescue the market because it loads a synchronized market before calculating the backing shortfall.

### Likelihood Explanation

Likelihood is conditional rather than immediate. An unprivileged actor must obtain enough listed assets to create or occupy a very large market, maintain high utilization for an extended period, and use a listing whose caps and interest-rate model allow the scaled value to approach `i128::MAX`. The demonstrated scenario needs billions of token units of aggregate collateral and roughly a billion whole units in the debt market, so it is not available on ordinary low-cap listings.

Nevertheless, neither the entry caps nor the index ceiling enforce the necessary `scaled_amount * index` bound over the market’s lifetime. An attacker can consolidate the roles shown as separate test addresses into one account by supplying both the target liquidity and unrelated collateral, then borrow the target asset and later trigger `update_indexes`. No privileged call, oracle manipulation, leaked key, or external service failure is required after a market with sufficient caps exists.

### Recommendation

Enforce a representable-value invariant during accrual instead of allowing the synchronous preflight to panic. In particular:

- Derive a dynamic index ceiling from the stored scaled total, such as the greatest index for which `scaled_amount * index / RAY` remains representable.
- Clamp `borrow_index` and `supply_index` at `min(protocol_ceiling, dynamic_ceiling)` before calculating utilization or interest rewards.
- Keep exit paths operational once either ceiling is reached, while skipping further value-growing accrual for that side.
- Alternatively, enforce entry caps conservative enough that every admitted scaled total remains representable at the protocol’s maximum index; this is much more restrictive and should be applied separately to supply and borrow exposure.
- Add regression coverage showing that `repay`, `withdraw`, `liquidate`, `clean_bad_debt`, `flash_loan`, `claim_revenue`, and `recapitalize` remain callable after the index is clamped.

### Proof of Concept

The repository already contains the decisive scenario in `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs`. Conceptually, the unprivileged sequence is:

1. Create an account with `Controller.supply(caller, 0, spoke_id, [(BIG18, 1_000_000_000 * 10^18)])`.
2. Supply sufficient unrelated listed collateral to the same account.
3. Call `Controller.borrow(caller, account_id, [(BIG18, 980_000_000 * 10^18)], Some(caller))`, producing 98% utilization.
4. Allow the configured high-utilization curve to compound until `borrowed * borrow_index / RAY` exceeds `i128::MAX`.
5. Any caller then invokes `Controller.update_indexes(caller, [BIG18])`, which calls the pool’s `update_indexes` and reaches `accrue_step`.
6. `scaled_to_original(borrowed, borrow_index)` panics with `MathOverflow`.
7. Subsequent `Controller.repay`, `Controller.withdraw`, `Controller.liquidate`, `Controller.clean_bad_debt`, and `Controller.recapitalize` calls reach `synced_market`, hit the same overflow before their mutations, and cannot recover the market.

The checked-in test performs this with `principal = 1_000_000_000 * 10^18`, `debt = principal * 98 / 100`, repeatedly advances time until `try_update_indexes_for(["BIG18"])` fails, and then verifies that both `try_withdraw_raw(BOB, "BIG18", 1)` and `try_repay(ALICE, "BIG18", 1.0)` fail with `MATH_OVERFLOW` while `borrow_index < MAX_BORROW_INDEX_RAY`. [10](#0-9)

### Citations

**File:** common/src/rates/simulate.rs (L51-64)
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
```

**File:** common/src/rates/scaling.rs (L12-16)
```rust
/// Converts a scaled `Ray` amount to its original (unscaled) value by
/// multiplying by `index`, rounding half up.
pub fn scaled_to_original(env: &Env, scaled: Ray, index: Ray) -> Ray {
    scaled.mul(env, index)
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

**File:** contracts/controller/src/lib.rs (L89-180)
```rust
impl ControllerInterface for Controller {
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

    /// Withdraws collateral to `to` or the caller and returns actual amounts in
    /// asset units. Zero withdraws an asset's full position. Requires owner or
    /// delegate authorization and post-withdrawal solvency.
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

    /// Socializes insolvent debt into the supply index and removes the account
    /// when remaining collateral is at or below the dust cap. Permissionless;
    /// requires caller authorization.
    fn clean_bad_debt(env: Env, caller: Address, account_id: u64) {
        positions::liquidation::process_clean_bad_debt(&env, &caller, account_id);
    }

    /// Flash-loans `amount` of `asset` to a deployed Wasm `receiver`, invoking
    /// its callback with `data`. The pool recovers principal plus fee before return.
    /// Permissionless; requires caller authorization.
    #[when_not_paused]
    fn flash_loan(
        env: Env,
        caller: Address,
        asset: HubAssetKey,
        amount: i128,
        receiver: Address,
        data: Bytes,
    ) {
        strategies::flash_loan::process_flash_loan(&env, &caller, &asset, amount, &receiver, &data);
    }
```

**File:** contracts/pool/README.md (L157-168)
```markdown
## Flow

Each mutation of an existing market runs this sequence:

```text
entrypoint (#[only_owner])
  → Cache::load             # read params + state, bump TTL
  → interest::global_sync   # accrue to now, in ≤1yr chunks
  → mutate                  # cache/shares.rs, cache/cash.rs
  → guards::*               # reserve, utilization, backing checks
  → commit → transfer_out → emit
```
```

**File:** tests/test-harness/tests/controller/large_positions_and_long_horizons.rs (L321-356)
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
    // The market is frozen: exits and repayments accrue first and hit the same panic.
    assert_contract_error(t.try_withdraw_raw(BOB, "BIG18", 1), errors::MATH_OVERFLOW);
    assert_contract_error(t.try_repay(ALICE, "BIG18", 1.0), errors::MATH_OVERFLOW);
```
