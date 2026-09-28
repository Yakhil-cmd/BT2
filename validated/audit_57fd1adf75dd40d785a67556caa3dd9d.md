### Title
Permanent market freeze from unscaled-debt `i128` overflow during accrual - (File: common/src/rates/simulate.rs)

### Summary
A sufficiently large borrow position can cause every subsequent accrual for that market to revert with `MathOverflow` before the borrow-index ceiling is reached, permanently preventing withdrawals, repayments, liquidations, and further accrual.

### Finding Description
`accrue_step` unconditionally reconverts the stored scaled debt and supply shares into RAY-denominated original values with `scaled_to_original` before calculating utilization and interest. [1](#0-0)   
`scaled_to_original` performs a checked `scaled * index / RAY` multiplication rather than saturating or using a representation that can carry market values larger than `i128::MAX`. [2](#0-1)   
The same accrual path later multiplies stored debt by both the old and new borrow indexes, creating additional overflow points even if utilization is guarded. [3](#0-2)   
`update_borrow_index` caps the index at `MAX_BORROW_INDEX_RAY`, but that cap bounds only the index and does not bound `borrowed * borrow_index / RAY`. [4](#0-3)   
Each mutating market operation loads the market cache and calls `interest::global_sync`, while the explicit index update path iterates requested `HubAssetKey` markets and calls the same function. [5](#0-4)   
Because the panic occurs inside `accrue_chunk` before `mark_accrued` or `commit`, the failed transaction does not advance `last_timestamp`, so every later operation repeats the same overflowing calculation. [6](#0-5)   

### Impact Explanation
The overflow can permanently freeze every user's funds in the affected `(hub_id, asset)` market. [7](#0-6)   
The regression test demonstrates that after the threshold is crossed, both supplier withdrawal and borrower repayment fail with `MathOverflow`, and the stored borrow index remains below `MAX_BORROW_INDEX_RAY`. [8](#0-7)   
The same accrual-first design also prevents debt reduction or liquidation from reaching the position-mutation logic once the market's aggregate scaled-debt value no longer fits `i128`. [9](#0-8)   
This is not a bounded-interest terminal state: index growth stops below the configured index ceiling because market valuation, not index multiplication, crosses the `i128` domain. [10](#0-9)   

### Likelihood Explanation
An unprivileged account can create the prerequisite state through ordinary `supply` and `borrow` calls, provided the market admits a sufficiently large cap and the account can provide the required tokens and collateral. [11](#0-10)   
The exercised configuration supplies one billion 18-decimal tokens, borrows 98% of them, and advances time under a steep valid rate curve until `update_indexes` fails. [12](#0-11)   
The attack does not require privileged calls, malformed parameters, oracle manipulation, reentrancy, or control of the token contract; it relies on interest accrual pushing an otherwise accepted market aggregate beyond the fixed-point range. [13](#0-12)   
The likelihood is constrained by the need for an extremely large accepted market and sustained high utilization, but once the state exists no further attacker action is required and the freeze is persistent. [14](#0-13)   

### Recommendation
Track and enforce a separate representable-value bound for market totals, not just bounds on token amounts and indexes. [15](#0-14)   
Before minting debt or supply shares, reject any aggregate scaled balance for which a plausible future index update can make `scaled * index / RAY` exceed `i128::MAX`, or clamp the effective market index at `floor(i128::MAX * RAY / scaled)` before accrual reaches an unrepresentable value. [4](#0-3)   
Alternatively, rework utilization, debt valuation, supplier valuation, and reward calculations to operate on widened values or bounded saturating totals so an out-of-range aggregate cannot abort the accrual preamble required by repayment and liquidation. [16](#0-15)   
Any fix must preserve the invariant that a user can always reduce debt and a liquidator can always reduce an unhealthy position, including when market value exceeds the representable RAY range. [17](#0-16)   

### Proof of Concept
1. List or use a market with 18 decimals, a lifted cap, and a steep valid interest-rate curve. [18](#0-17) 
2. Call `supply` with `1_000_000_000 * 10^18` base units so the market stores approximately `10^36` scaled supply shares at an index near one RAY. [19](#0-18) 
3. Using collateral in another market, call `borrow` for approximately 98% of that balance; at an index near one RAY this creates approximately `9.8 * 10^35` scaled debt shares. [20](#0-19) 
4. Advance ledger time and repeatedly call `update_indexes` for the same `HubAssetKey` until `borrowed * borrow_index / RAY` exceeds `i128::MAX`. [21](#0-20) 
5. The next accrual reverts in `scaled_to_original` before storing a capped index, after which `withdraw`, `repay`, and subsequent `update_indexes` calls all repeat the failing accrual. [8](#0-7)

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

**File:** common/src/rates/scaling.rs (L12-16)
```rust
/// Converts a scaled `Ray` amount to its original (unscaled) value by
/// multiplying by `index`, rounding half up.
pub fn scaled_to_original(env: &Env, scaled: Ray, index: Ray) -> Ray {
    scaled.mul(env, index)
}
```

**File:** common/src/rates/scaling.rs (L18-25)
```rust
/// Converts an asset-unit `cap` to a scaled `Ray` value, rounding down.
///
/// The division saturates at `i128::MAX` instead of panicking, so the cap check
/// fails open rather than trapping an entry path. The asset-to-RAY
/// rescale still panics on overflow; listings validate caps with
/// [`crate::validation::require_cap_within_asset_domain`]. Position accounting
/// uses [`calculate_scaled_supply`] and [`calculate_scaled_borrow`], which panic
/// on overflow.
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

**File:** common/src/rates/index.rs (L73-83)
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
```

**File:** contracts/pool/src/ops/market.rs (L60-72)
```rust
/// Accrues interest for each market in `hub_assets` and emits one state event
/// per market.
///
/// Always commits state so same-ledger simulation records the write footprint
/// needed if time advances before transaction inclusion.
pub(crate) fn accrue(env: &Env, hub_assets: Vec<HubAssetKey>) {
    renew_instance(env);

    for hub_asset in hub_assets.iter() {
        let mut cache = Cache::load(env, &hub_asset);
        interest::global_sync(env, &mut cache);
        events::emit_market_state(env, cache.commit());
    }
```

**File:** contracts/pool/src/interest.rs (L20-52)
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

**File:** contracts/controller/src/lib.rs (L130-150)
```rust
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
```
