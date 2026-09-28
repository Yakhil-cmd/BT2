### Title
Accrued RAY position values can overflow `i128` and permanently freeze a market - ([File: common/src/rates/simulate.rs])

### Summary
Interest accrual multiplies total scaled supply and debt shares by their indexes before mutating a market, and any result exceeding `i128::MAX` reverts with `MathOverflow`. Because every pool mutation and the permissionless `Controller::update_indexes` path performs accrual first, crossing this arithmetic boundary can permanently prevent repayment, withdrawal, liquidation, and further index updates for that market. [1](#0-0) [2](#0-1) [3](#0-2) 

### Finding Description
`accrue_step` computes `borrowed * borrow_index` and `supplied * supply_index` through `scaled_to_original` before calculating utilization and the next indexes. [1](#0-0) 
`scaled_to_original` invokes `Ray::mul`, which delegates to overflow-safe `mul_div_half_up` and returns `MathOverflow` when the resulting RAY value cannot fit `i128`. [4](#0-3) [5](#0-4) [6](#0-5) 
The borrow index is capped at `MAX_BORROW_INDEX_RAY`, but that cap is applied after calculating the new index and does not bound the separate scaled-share times index value used earlier in the accrual step. [7](#0-6) 
Every pool operation leg loads `synced_market`, and `synced_market` always runs `global_sync` before the operation-specific mutation. [8](#0-7) 
`Controller::update_indexes(caller, assets)` is permissionless except for caller authorization and forwards the selected `HubAssetKey` list to the pool accrual entrypoint. [3](#0-2) [9](#0-8) 
An attacker can therefore create or use a sufficiently large supplied and borrowed market under configured caps, allow high-utilization interest to increase the index until `scaled * index / RAY` exceeds `i128::MAX`, and then call `update_indexes`; once the accrual boundary is crossed, subsequent calls encounter the same overflow before any state transition can commit. [10](#0-9) [11](#0-10) 
The repository’s own long-horizon test demonstrates this state: `update_indexes` fails with `MathOverflow` before the borrow-index cap engages, and attempted withdrawal and repayment fail with the same error. [12](#0-11) 

### Impact Explanation
The affected market becomes unable to operate: suppliers cannot withdraw pool funds, borrowers cannot repay, liquidators cannot cure positions, and the pool cannot commit further index updates because all of those paths accrue first. [8](#0-7) [13](#0-12) 
This is a permanent freeze of user funds and market debt rather than a temporary revert because `last_timestamp` is only advanced after all accrual chunks complete, so a failed transaction leaves the same overflowing elapsed interval for the next call. [10](#0-9) 

### Likelihood Explanation
Triggering the state requires a market with very large scaled positions and enough elapsed high-utilization accrual for the resulting RAY value to exceed `i128::MAX`; configured spoke caps, asset supply, collateral requirements, and the borrow-rate model constrain practical reachability. [14](#0-13) [7](#0-6) 
The admitted numeric domain explicitly permits values whose future accrued totals may no longer fit, and the repository test reaches the failure with a billion-unit 18-decimal market at sustained 98% utilization. [15](#0-14) [16](#0-15) 

### Recommendation
Enforce a protocol-wide scaled-share ceiling that guarantees `scaled * MAX_INDEX / RAY <= i128::MAX`, rather than relying only on token-unit caps whose safety changes as indexes grow. [7](#0-6) [14](#0-13) 
Apply that bound when minting supply or debt shares, including aggregate exposure across all spokes for the same physical pool market, and add regression coverage proving `update_indexes`, `repay`, `withdraw`, and `liquidate` remain executable at the configured maximum. [17](#0-16) [8](#0-7) 
Alternatively, redesign accrual so utilization and rewards use saturating or widened totals and can still advance `last_timestamp` while clamping indexes, avoiding a state where no settlement path can execute. [18](#0-17) [10](#0-9) 

### Proof of Concept
1. A liquidity-supplying address calls `Controller::supply(caller, account_id, spoke_id, assets)` with a large positive amount for an 18-decimal borrowable market, within the configured spoke cap. [19](#0-18) 
2. The same or another unprivileged account supplies sufficient collateral and calls `Controller::borrow(caller, account_id, borrows, to)` to place the market at sustained high utilization. [20](#0-19) 
3. After time advances and the borrow index grows, any address calls `Controller::update_indexes(caller, vec![hub_asset])`. [3](#0-2) 
4. The pool’s `global_sync` calls `accrue_step`, whose `scaled_to_original(borrowed, borrow_index)` or `scaled_to_original(supplied, supply_index)` overflows `i128` and panics with `MathOverflow`. [10](#0-9) [21](#0-20) 
5. Because `withdraw`, `repay`, liquidation settlement, and later `update_indexes` calls all load an interest-synced market first, they repeat the same overflowing multiplication before reaching their own logic. [8](#0-7) 
6. The existing test `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` demonstrates this sequence and asserts `MathOverflow` for `update_indexes`, `withdraw`, and `repay` while the stored borrow index remains below `MAX_BORROW_INDEX_RAY`. [22](#0-21)

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

**File:** contracts/pool/src/interest.rs (L20-33)
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
```

**File:** contracts/controller/src/lib.rs (L90-102)
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
```

**File:** contracts/controller/src/lib.rs (L104-115)
```rust
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

**File:** contracts/controller/src/spoke_usage.rs (L142-156)
```rust
/// Adds scaled usage and enforces the asset-unit cap converted to RAY
/// with `index` and `decimals`.
fn enforce_spoke_cap(
    env: &Env,
    side: UsageSide,
    usage: &SpokeUsageRaw,
    delta_scaled: Ray,
    cap: i128,
    index: Ray,
    decimals: u32,
) -> Ray {
    let cap_scaled = calculate_scaled_cap(env, cap, decimals, index);
    let next_scaled = Ray::from(side.scaled(usage)).checked_add(env, delta_scaled);
    assert_with_error!(env, next_scaled <= cap_scaled, side.cap_error());
    next_scaled
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

**File:** contracts/pool/src/cache/scale.rs (L29-47)
```rust
    /// Converts an asset deposit into scaled supply shares (floor at the supply index).
    pub(crate) fn calculate_scaled_supply(&self, amount: i128) -> Ray {
        calculate_scaled_supply(
            &self.env,
            amount,
            self.params.asset_decimals,
            self.supply_index,
        )
    }

    /// Converts an asset borrow into scaled debt shares (ceil at the borrow index).
    pub(crate) fn calculate_scaled_borrow(&self, amount: i128) -> Ray {
        calculate_scaled_borrow(
            &self.env,
            amount,
            self.params.asset_decimals,
            self.borrow_index,
        )
    }
```
