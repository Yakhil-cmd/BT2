### Title
Unchecked RAY debt-valuation overflow permanently freezes a market - ([File: common/src/rates/index.rs])

### Summary
Market accrual computes total debt as `borrowed * borrow_index` and requires the RAY-denominated result to fit `i128`. Even though intermediate multiplication is widened, converting a representable debt value back to `i128` fails once it exceeds `i128::MAX`. Because every state-changing market leg synchronizes interest first, a single public `update_indexes` call can permanently brick subsequent withdrawals, repayments, liquidations, and further index updates.

### Finding Description
`calculate_supplier_rewards` computes both `borrowed.mul(env, old_borrow_index)` and `borrowed.mul(env, new_borrow_index)`. `Ray::mul` correctly uses exact widened intermediate arithmetic, but still requires the final RAY value to fit `i128`. [1](#0-0) [2](#0-1) 

All ordinary pool legs call `load_leg`, which loads the market and invokes `interest::global_sync` before the operation is applied. [3](#0-2)  `global_sync` repeatedly calls `accrue_chunk`, which invokes `accrue_step` and therefore evaluates total supplied/borrowed values before committing a new timestamp. [4](#0-3) 

The borrow-index ceiling does not prevent this condition: `update_borrow_index` caps the index itself, but the overflow occurs when total scaled debt is multiplied by an index that is still below the cap. [5](#0-4)  The repository’s long-horizon test demonstrates this exact transition: `try_update_indexes_for(["BIG18"])` fails with `MathOverflow`, after which both `withdraw` and `repay` fail during their mandatory accrual step. [6](#0-5) 

The strongest unprivileged trigger is the public controller `update_indexes` call for a heavily supplied and borrowed market, using a vector containing that market’s `HubAssetKey`. After the first failed sync, `withdraw`, `repay`, `borrow`, `liquidate`, `clean_bad_debt`, `flash_loan`, `recapitalize`, and other market legs cannot pass their initial synchronization for that market.

### Impact Explanation
This permanently freezes all accounting-dependent activity for the affected hub/asset market. Suppliers cannot withdraw, borrowers cannot repay, liquidators cannot liquidate, and recapitalization cannot proceed because those paths all synchronize the same market before acting. [3](#0-2)  Since the panic happens before `mark_accrued`, the market state remains stuck at the old timestamp and every retry reaches the same overflowing valuation. [7](#0-6) 

This meets the permanent-freezing impact class rather than a temporary transaction failure.

### Likelihood Explanation
The condition requires a very large market and sustained high-utilization accrual, but no privileged runtime action is needed to trigger it once such a market exists. Ordinary users can supply the asset, an overcollateralized borrower can maintain high utilization, and anyone can call `update_indexes`. The in-repository test uses a one-billion-token, 18-decimal market at 98% utilization and shows that the debt-value ceiling is reached before the borrow-index cap. [6](#0-5) 

Likelihood is constrained by the required liquidity, collateral, and elapsed accrual, but it is not prevented by checked arithmetic, market caps alone, or the index ceiling.

### Recommendation
Do not let accrual depend on an `i128`-representable total debt valuation. Store or compute total debt with a wider representation during accrual, or cap accrued debt/accounting values atomically with the borrow index before converting back to `i128`. If saturation is intended, it must preserve a recoverable state and should not make withdrawals, repayment, liquidation, or recapitalization permanently impossible.

At minimum, add a pre-accrual bound for `borrowed` relative to the prospective `borrow_index`, and stop index growth before `borrowed * index / RAY` can exceed `i128::MAX`. Apply equivalent protection to total supplied value in `update_supply_index` and bad-debt socialization.

### Proof of Concept
1. Configure an admitted 18-decimal market whose caps permit approximately `1_000_000_000 * 10^18` base units.
2. Call `supply` with that amount for the target `HubAssetKey`.
3. From a sufficiently collateralized account, call `borrow` for approximately 98% of the supplied amount.
4. Let interest accrue at the market’s high-utilization rate until `borrowed * borrow_index / RAY > i128::MAX`.
5. Call `update_indexes` with `hub_assets = vec![HubAssetKey { hub_id, asset }]`.
6. The call fails with `MathOverflow` inside `calculate_supplier_rewards`.
7. Subsequent `withdraw`, `repay`, `liquidate`, `borrow`, `clean_bad_debt`, `recapitalize`, and `update_indexes` calls for the same market fail at their mandatory synchronization step.

The harness test `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` encodes this sequence and asserts both `withdraw` and `repay` fail with `MathOverflow`. [6](#0-5)

### Citations

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

**File:** contracts/pool/src/ops/mod.rs (L29-47)
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
}
```

**File:** contracts/pool/src/interest.rs (L20-53)
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
}
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
