### Title
RAY-value overflow in mandatory interest accrual permanently freezes an oversized market - ([File: common/src/rates/simulate.rs](common/src/rates/simulate.rs))

### Summary
`accrue_step` converts the market's entire scaled borrow and supply balances into RAY-denominated values before updating the borrow index. Those conversions panic when `scaled_amount * index / RAY` exceeds `i128::MAX`, even though the index itself remains below `MAX_BORROW_INDEX_RAY`. Because every pool mutation performs this accrual first, a sufficiently large and heavily utilized market reaches a state where withdrawals, repayments, liquidations, recapitalization, parameter updates, and further index updates all revert with `MathOverflow`. [1](#0-0) [2](#0-1) 

### Finding Description
The pool stores supply and debt as RAY-scaled shares. During each accrual, `accrue_step` computes `borrowed_original` and `supplied_original` through `scaled_to_original`, which calls the non-saturating half-up `Ray::mul`. The fixed-point primitive uses an `I256` intermediate, but returns `None` when the final result cannot fit in `i128`; callers convert that into `GenericError::MathOverflow`. [2](#0-1) [3](#0-2) 

The borrow index is capped only after `update_borrow_index` computes the next index. That cap does not constrain the value represented by `borrowed * borrow_index / RAY`; with `MAX_BORROW_INDEX_RAY = 10^36`, a market holding approximately `10^36` scaled units crosses the `i128` result ceiling near an index multiple of 170, long before the index cap of `10^9`. [4](#0-3) [5](#0-4) 

`global_sync` runs `accrue_step` before each market mutation and is therefore a mandatory prefix for the pool's owner-mediated operations. The repository's regression test demonstrates the concrete cliff: after an 18-decimal market holds one billion whole tokens and sustains 98% utilization, `update_indexes` returns `MathOverflow`; subsequent `withdraw` and `repay` calls fail for the same reason while the borrow index remains below its configured maximum. [6](#0-5) [7](#0-6) 

The user-facing entrypoints are reachable without privileged pool access: `Controller::supply`, `borrow`, `withdraw`, `repay`, `liquidate`, `clean_bad_debt`, and `update_indexes` all forward through the controller, which is the pool owner. [8](#0-7) [9](#0-8) 

### Impact Explanation
This is permanent freezing of funds and protocol insolvency for the affected `(hub_id, asset)` market under the deployed code. Suppliers cannot withdraw principal or yield, borrowers cannot repay, liquidators cannot reduce underwater debt, and bad-debt cleanup cannot proceed because each operation first re-enters the overflowing accrual calculation. `recapitalize` cannot provide a recovery path because it is also a pool market mutation that loads and accrues the market. Governance parameter replacement likewise calls `update_indexes` before `update_params`, so changing the rate model cannot avoid the already-overflowing accrual. [10](#0-9) [11](#0-10) 

A third-party attacker can deliberately establish the oversized book and leave it at sustained high utilization. Other users' deposits in the same physical market then become frozen even though the attacker supplied only their own assets and used only public controller entrypoints. [12](#0-11) 

### Likelihood Explanation
Likelihood is medium-low but nonzero: the attack requires an asset with a very large admitted cap, enough token liquidity to create approximately `10^36` scaled units, collateral capable of borrowing most of that book, and sustained high utilization long enough for the index multiple to exceed roughly 170. Those are market-scale prerequisites rather than privileged actions. Once the state exists, expiration is deterministic: no oracle manipulation, race, reentrancy, or privileged action is required. The existing test reaches the cliff within the modeled 40-year bound on the configured stress curve. [13](#0-12) 

### Recommendation
Do not let market accrual depend on converting aggregate scaled balances to `i128` RAY totals after the balances have grown beyond the representable domain. Enforce a conservative maximum scaled supply/debt derived from the maximum permitted index, or rework aggregate utilization and interest calculations to operate on checked `I256` values without requiring an `i128` market total. The cap must cover aggregate `supplied` and `borrowed`, not merely per-call amounts, and should be enforced by `supply`, `borrow`, strategy debt minting, revenue minting, and any path that increases shares. Add a deployment-facing bound that accounts for `MAX_BORROW_INDEX_RAY`, `MAX_SUPPLY_INDEX_RAY`, and each asset's decimal normalization. [14](#0-13) [15](#0-14) 

A safe interim control is to reject any operation that would make either aggregate's maximum future RAY value unrepresentable, and to cap indexes before their use in aggregate valuation. The fallback should preserve repayment and withdrawal rather than simply saturating debt value, since saturation would misstate solvency.

### Proof of Concept
Concrete flow, matching the repository test:

1. Governance admits an 18-decimal market with the existing steep rate parameters and sufficiently high supply/borrow caps.
2. Supplier `BOB` calls:
   ```rust
   controller.supply(
       bob,
       0,
       spoke_id,
       vec![(big18_key, 1_000_000_000 * 10i128.pow(18))],
   );
   ```
   This creates approximately `10^36` RAY-scaled supply shares. [16](#0-15) 
3. Borrower `ALICE` supplies separate collateral and calls `controller.borrow(alice, alice_account, vec![(big18_key, 980_000_000 * 10i128.pow(18))], None)`, placing the market near 98% utilization.
4. Any address periodically calls:
   ```rust
   controller.update_indexes(caller, vec![big18_key]);
   ```
   The controller only requires caller authorization and forwards to the owner-gated pool accrual. [9](#0-8) 
5. Once the index multiple raises `borrowed * borrow_index / RAY` or `supplied * supply_index / RAY` past `i128::MAX`, `scaled_to_original` panics inside `accrue_step`.
6. All subsequent operations against the market accrue first and fail:
   ```rust
   controller.withdraw(bob, bob_account, vec![(big18_key, 0)], None);
   controller.repay(alice, alice_account, vec![(big18_key, debt)]);
   controller.liquidate(liquidator, alice_account, payments, SeizeMode::Transfer);
   controller.clean_bad_debt(caller, alice_account);
   controller.recapitalize(payer, big18_key, amount);
   ```
   The checked regression test confirms `MathOverflow` for `update_indexes`, `withdraw`, and `repay` after the cliff. [17](#0-16)

### Citations

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

**File:** common/src/rates/index.rs (L29-45)
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

**File:** tests/test-harness/tests/controller/large_positions_and_long_horizons.rs (L315-360)
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
    std::println!(
        "ray-value cliff reached after {years} years at 98 percent utilization on the XLM curve; last index x{:.1}",
        last.borrow_index as f64 / RAY as f64
    );
```

**File:** contracts/controller/src/lib.rs (L90-164)
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

**File:** contracts/pool/src/lib.rs (L174-194)
```rust
    /// Accrues interest for each market in `hub_assets` through the current
    /// ledger time. Commits state even with no elapsed time to reserve the write
    /// footprint, and emits its market state event. Restricted to the owner.
    #[only_owner]
    fn update_indexes(env: Env, hub_assets: Vec<HubAssetKey>) {
        ops::market::accrue(&env, hub_assets);
    }

    /// Credits cash up to the market's backing shortfall
    /// (`guards::backing_shortfall`) and transfers the excess back to `payer`.
    /// The controller transfers `amount` in before this call. Restricted to
    /// the owner; returns a [`PoolAmountMutation`] with the amount applied.
    #[only_owner]
    fn recapitalize(
        env: Env,
        hub_asset: HubAssetKey,
        payer: Address,
        amount: i128,
    ) -> PoolAmountMutation {
        ops::recapitalize::apply(&env, hub_asset, payer, amount)
    }
```

**File:** contracts/pool/README.md (L157-176)
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

Checks-effects-interactions holds everywhere except `flash_loan`, which inverts
by nature and compensates with balance reconciliation.

`ops::run_batch` gives each entry its own `Cache::load`, so two entries hitting
the same market in one batch compose correctly — the second reads the first's
committed state. Indexers: a market touched twice emits two snapshots in one
`PoolMarketStateBatchEvent`; take the last. An empty batch emits nothing.
```
