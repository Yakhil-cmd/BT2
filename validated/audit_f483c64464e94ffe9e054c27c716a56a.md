### Title
RAY-value overflow during interest accrual permanently freezes an oversized market - (File: common/src/rates/index.rs)

### Summary
A sufficiently large, high-utilization market can reach an `i128` overflow while calculating accrued debt before the configured borrow-index ceiling is reached, after which every operation that must synchronize the market reverts and suppliers, borrowers, and liquidators are permanently blocked. [1](#0-0) [2](#0-1) 

### Finding Description
Every pool mutation loads the market through `synced_market`, which calls `global_sync` before the operation can proceed. [3](#0-2)  `global_sync` applies all elapsed-time accrual chunks through `accrue_step` before committing the synchronized state. [4](#0-3)  During each step, `calculate_supplier_rewards` evaluates `borrowed * old_borrow_index` and `borrowed * new_borrow_index` in the RAY domain using panicking fixed-point multiplication, then subtracts the two totals. [5](#0-4) 

The configured borrow-index cap is applied only to the index produced by `old_index * interest_factor`; it does not bound the much larger `borrowed * index` value used for interest accounting. [6](#0-5)  Consequently, a scaled debt balance can exceed the representable RAY-value domain while the index is still far below `MAX_BORROW_INDEX_RAY`, causing `MathOverflow` rather than an orderly cap or graceful failure. [7](#0-6) 

An unprivileged user can trigger the transition through the controller’s `update_indexes` path for the affected `HubAssetKey`; the controller forwards the vector to the pool’s `update_indexes`, which iterates the requested markets and calls `global_sync`. [8](#0-7) [9](#0-8) 

### Impact Explanation
Once the next accrual step overflows, `repay`, `withdraw`, liquidation, supply, borrow, recapitalization, revenue claims, and parameter replacement all need to synchronize the market and therefore encounter the same panic. [10](#0-9) [11](#0-10)  The repository’s long-horizon test explicitly demonstrates that both withdrawal and repayment revert with `MATH_OVERFLOW` after the accrual cliff is reached. [12](#0-11)  This is permanent freezing of user funds and loss of liquidation liveness for that market, which can also leave bad debt unable to be processed. [13](#0-12) 

### Likelihood Explanation
The trigger requires an exceptionally large market and sustained interest accrual: the regression test uses an 18-decimal market supplied with `1_000_000_000 * 10^18` base units and approximately 98% utilization, then advances ledger time until accrual fails. [14](#0-13)  Those conditions are nevertheless reachable through permitted supply and borrow flows when governance admits caps large enough, and no privileged or malformed call is required to execute the failing `update_indexes` transition. [15](#0-14)  Severity is Medium because the impact is permanent market-wide freezing, but exploitation depends on extreme capitalization and prolonged utilization.

### Recommendation
Represent accrued debt and supplied-value intermediates with `I256`, or enforce market and position caps derived from `i128::MAX`, `RAY`, and `MAX_BORROW_INDEX_RAY`/`MAX_SUPPLY_INDEX_RAY` so every scaled balance multiplied by its maximum possible index remains representable. Accrual should also apply the index ceiling before evaluating reward totals, or handle an unrepresentable accrued value as an explicit bounded-debt state instead of aborting every synchronization path. Add a boundary test proving that a market admitted under maximum caps can always accrue through `MAX_BORROW_INDEX_RAY` without `MathOverflow`. [16](#0-15) [1](#0-0) 

### Proof of Concept
The existing regression sequence is:

1. Configure an 18-decimal borrow market with the steep XLM rate curve, disabled max utilization, and sufficiently lifted caps, plus a collateral market. [17](#0-16) 
2. Supply `principal = 1_000_000_000 * 10^18` base units to the 18-decimal market. [18](#0-17) 
3. Supply enough collateral and borrow `principal * 98 / 100`, establishing approximately 98% utilization. [19](#0-18) 
4. Advance ledger time in yearly increments and call controller `update_indexes` with a `Vec<HubAssetKey>` containing the market’s `(hub_id, asset)`. [20](#0-19) [9](#0-8) 
5. The call eventually returns `MATH_OVERFLOW` while the stored borrow index remains below `MAX_BORROW_INDEX_RAY`. [7](#0-6) 
6. Subsequent `withdraw` and `repay` calls also return `MATH_OVERFLOW`, confirming the permanent freeze. [12](#0-11)

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

**File:** tests/test-harness/tests/controller/large_positions_and_long_horizons.rs (L316-356)
```rust
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

**File:** contracts/pool/src/ops/mod.rs (L29-45)
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

**File:** contracts/pool/src/lib.rs (L174-180)
```rust
    /// Accrues interest for each market in `hub_assets` through the current
    /// ledger time. Commits state even with no elapsed time to reserve the write
    /// footprint, and emits its market state event. Restricted to the owner.
    #[only_owner]
    fn update_indexes(env: Env, hub_assets: Vec<HubAssetKey>) {
        ops::market::accrue(&env, hub_assets);
    }
```

**File:** contracts/pool/src/ops/market.rs (L50-57)
```rust
/// Accrues interest under the old model, commits it, then replaces the interest
/// and flash-loan parameters and validates them against the stored decimals.
pub(crate) fn replace_rate_model(env: &Env, hub_asset: HubAssetKey, model: InterestRateModel) {
    ops::renewed_market(env, &hub_asset).commit();

    let params = storage::write_rate_model(env, &hub_asset, &model);
    params.verify(env);
    events::emit_market_params(env, hub_asset.hub_id, hub_asset.asset, params);
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
