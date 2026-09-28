### Title
RAY-scaled accrual overflows `i128` and permanently freezes a market - (File: common/src/rates/index.rs)

### Summary

Pool accrual computes RAY-denominated market values by multiplying scaled share totals by the borrow or supply index. Those products can exceed `i128::MAX` before the borrow index reaches its configured `MAX_BORROW_INDEX_RAY` cap, causing `MathOverflow` rather than clamping the accrued value. [1](#0-0) 

Every pool mutation loads the market through `synced_market`, which runs `interest::global_sync` before the requested operation. [2](#0-1)  Once the scaled debt or supply value crosses the representable range, subsequent accrual attempts always panic, so repayment, withdrawal, liquidation, recapitalization, parameter updates, and even `update_indexes` cannot proceed. [3](#0-2) 

### Finding Description

`accrue_step` first converts the stored scaled balances to original RAY values: [4](#0-3) 

```rust
let borrowed_original = scaled_to_original(env, borrowed, borrow_index);
let supplied_original = scaled_to_original(env, supplied, supply_index);
```

`scaled_to_original` delegates to `Ray::mul`, which panics when the exact scaled value does not fit `i128`. [5](#0-4) 

The subsequent reward calculation repeats the same unchecked-in-effect multiplication for old and new debt values: [1](#0-0) 

```rust
let old_total_debt = borrowed.mul(env, old_borrow_index);
let new_total_debt = borrowed.mul(env, new_borrow_index);
```

The borrow index cap is applied only after `old_index.mul(interest_factor)` succeeds and only bounds the index itself; it does not bound `borrowed * index`. [6](#0-5)  Similarly, supplier-reward distribution multiplies `supplied` by the current supply index before adding rewards. [7](#0-6) 

An unprivileged attacker can create and fund their own account through `supply`, borrow a large position through `borrow`, and later call the permissionless `update_indexes` maintenance function with the affected `HubAssetKey`. [8](#0-7) [9](#0-8) 

### Impact Explanation

This is a permanent freezing-of-funds condition for the affected market. Because all state-changing pool paths accrue first, once either value multiplication exceeds `i128::MAX`, users cannot repay debt, withdraw collateral or supplied assets, liquidate unhealthy accounts, recapitalize the market, claim revenue, or perform another index update. [2](#0-1) 

Governance repair through `update_params` also cannot bypass the failure because it explicitly calls `pool_update_indexes_call` before writing new parameters. [10](#0-9)  The panic therefore traps the market's existing token balances and debt positions rather than merely rejecting one oversized user input.

### Likelihood Explanation

Likelihood is conditional on a market accumulating very large scaled balances and sustained interest such that `scaled_amount * index / RAY > i128::MAX`. The attacker does not need privileged access, malformed tokens, a callback, or an oracle deviation: they only need sufficient collateral and a market configuration whose caps and rate curve permit the required borrow and accrual. [11](#0-10) 

The issue is easiest to reach on a large, highly utilized market where the borrow index grows faster than the supply index. The overflow threshold is a RAY-denominated value limit, not the nominal token cap, so an index below the protocol index ceiling can still produce an unrepresentable total. [12](#0-11) 

### Recommendation

Make accrual overflow-safe before evaluating either market value:

- Bound each index update by the maximum index representable for the stored scaled balance, e.g. `max_index = i128::MAX * RAY / scaled`.
- Alternatively, represent market totals in `I256` throughout accrual and convert back only after safely reducing the represented range.
- Apply the same protection to `borrowed * borrow_index`, `supplied * supply_index`, old/new debt comparisons, supplier rewards, and bad-debt valuation.
- Prefer an explicit accrual-clamped state over `MathOverflow`, and emit an event when accrual reaches the representable bound.
- Add a production-path regression test proving that `repay` and `withdraw` remain callable after the market reaches the boundary.

### Proof of Concept

1. Attacker calls `supply(caller, 0, spoke_id, [(collateral_key, large_amount)])` to create an account and deposit collateral.
2. Attacker calls `borrow(caller, account_id, [(debt_key, large_debt)], None)` and drives the debt market to high utilization.
3. Time elapses while the position remains open.
4. Attacker calls `update_indexes(caller, [debt_key])`.
5. `update_indexes` reaches `global_sync`, which invokes `accrue_step`. [13](#0-12) 
6. `accrue_step` calls `scaled_to_original(borrowed, borrow_index)` and then `calculate_supplier_rewards`, which computes `borrowed.mul(old_borrow_index)` and `borrowed.mul(new_borrow_index)`. [14](#0-13) [15](#0-14) 
7. When `borrowed * borrow_index / RAY` exceeds `i128::MAX`, `Ray::mul` panics with `MathOverflow`.
8. Any later `repay`, `withdraw`, `liquidate`, `clean_bad_debt`, or `recapitalize` touching that market loads through `synced_market` and panics at the same accrual step before applying its own accounting, permanently freezing the market's funds. [2](#0-1)

### Citations

**File:** common/src/rates/index.rs (L11-19)
```rust
/// Applies `interest_factor` to `old_index` to produce the new borrow index,
/// capped at `MAX_BORROW_INDEX_RAY`.
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

**File:** common/src/rates/simulate.rs (L51-71)
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
```

**File:** common/src/rates/scaling.rs (L12-16)
```rust
/// Converts a scaled `Ray` amount to its original (unscaled) value by
/// multiplying by `index`, rounding half up.
pub fn scaled_to_original(env: &Env, scaled: Ray, index: Ray) -> Ray {
    scaled.mul(env, index)
}
```

**File:** contracts/controller/README.md (L73-79)
```markdown
| `supply` | `fn supply( env: Env, caller: Address, account_id: u64, spoke_id: u32, assets: Vec<(HubAssetKey, i128)>, ) -> u64` | blocked by global pause | Supplies `assets` as collateral to `account_id` in spoke `spoke_id`, creating a new account when `account_id` is 0, and returns the account id. |
| `borrow` | `fn borrow( env: Env, caller: Address, account_id: u64, borrows: Vec<(HubAssetKey, i128)>, to: Option<Address>, )` | blocked by global pause | Borrows `borrows` against `account_id`'s collateral, sending the funds to `to` if provided or to the caller otherwise; reverts if the resulting position breaches the account's solvency limits. |
| `withdraw` | `fn withdraw( env: Env, caller: Address, account_id: u64, withdrawals: Vec<(HubAssetKey, i128)>, to: Option<Address>, ) -> Vec<(HubAssetKey, i128)>` | — | Withdraws `withdrawals` from `account_id`'s supplied collateral, sending the funds to `to` if provided or to the caller otherwise, and returns the amounts actually withdrawn; a zero amount for an asset withdraws the entire position. |
| `repay` | `fn repay(env: Env, caller: Address, account_id: u64, payments: Vec<(HubAssetKey, i128)>)` | — | Repays `payments` against `account_id`'s debt positions, pulling the funds from the caller and refunding any excess. |
| `liquidate` | `fn liquidate( env: Env, liquidator: Address, account_id: u64, debt_payments: Vec<(HubAssetKey, i128)>, seize_mode: SeizeMode, ) -> u64` | — | Liquidates `account_id` by having `liquidator` repay `debt_payments` and seizing collateral at a bonus scaled by the account's health factor. Returns the `Credit` receiver's account id, or 0 for `Transfer`. |
| `clean_bad_debt` | `fn clean_bad_debt(env: Env, caller: Address, account_id: u64)` | — | Socializes `account_id`'s debt into the supply index and removes the account when it is insolvent and its remaining collateral value is at or below the dust threshold; reverts otherwise. |

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

**File:** common/src/rates/curve.rs (L21-68)
```rust
pub fn calculate_annual_borrow_rate(env: &Env, utilization: Ray, params: &MarketParams) -> Ray {
    let utilization = if utilization > Ray::ONE {
        Ray::ONE
    } else {
        utilization
    };

    let annual_rate = if utilization < params.mid_utilization {
        let contribution = utilization
            .mul(env, params.slope1)
            .div(env, params.mid_utilization);
        params.base_borrow_rate.checked_add(env, contribution)
    } else if utilization < params.optimal_utilization {
        let excess = utilization.checked_sub(env, params.mid_utilization);
        let range = params
            .optimal_utilization
            .checked_sub(env, params.mid_utilization);
        let contribution = excess.mul(env, params.slope2).div(env, range);
        params
            .base_borrow_rate
            .checked_add(env, params.slope1)
            .checked_add(env, contribution)
    } else {
        let base_rate = params
            .base_borrow_rate
            .checked_add(env, params.slope1)
            .checked_add(env, params.slope2);
        let excess = utilization.checked_sub(env, params.optimal_utilization);
        let range = Ray::ONE.checked_sub(env, params.optimal_utilization);
        let contribution = excess.mul(env, params.slope3).div(env, range);
        base_rate.checked_add(env, contribution)
    };

    if annual_rate > params.max_borrow_rate {
        params.max_borrow_rate
    } else {
        annual_rate
    }
}

/// Computes the per-millisecond borrow rate (RAY) for `utilization`.
///
/// Divides [`calculate_annual_borrow_rate`] by [`MILLISECONDS_PER_YEAR`],
/// rounding half up.
pub fn calculate_borrow_rate(env: &Env, utilization: Ray, params: &MarketParams) -> Ray {
    calculate_annual_borrow_rate(env, utilization, params)
        .div_by_int(env, MILLISECONDS_PER_YEAR as i128)
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
