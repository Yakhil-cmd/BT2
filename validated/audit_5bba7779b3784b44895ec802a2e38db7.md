### Title
RAY index growth can overflow mandatory accrual math and permanently freeze a market - ([File: contracts/pool/src/interest.rs])

### Summary

A sufficiently large market can grow its borrow index until unscaling total debt overflows `i128`, after which every state-changing market path reverts during mandatory interest accrual. [1](#0-0) [2](#0-1) 

### Finding Description

Every market operation loads the market and calls `global_sync`, which repeatedly calls `accrue_chunk` before committing the updated indexes and revenue. [3](#0-2) [4](#0-3) 

The accrual path derives utilization from `scaled_to_original(borrowed, borrow_index)` and `scaled_to_original(supplied, supply_index)`. [5](#0-4) 

Those products are represented in `i128`; `calculate_supplier_rewards` similarly multiplies total scaled debt by the old and new borrow indexes. [6](#0-5) 

`update_borrow_index` clamps the index only after multiplying it by the interest factor, so it does not cap the scaled-debt value itself below `i128::MAX`. [7](#0-6) 

An unprivileged user can reach this state through `supply`, `borrow`, and the permissionless `update_indexes` entrypoint. [8](#0-7) [9](#0-8) 

The repository’s deterministic long-horizon test demonstrates the failure: after sustained 98% utilization on an 18-decimal billion-token market, `update_indexes` fails with `MathOverflow`, and subsequent repayment and withdrawal calls hit the same failure. [10](#0-9) 

### Impact Explanation

Once the scaled debt multiplied by the next index exceeds the representable value range, accrual panics before the market commits a new timestamp or rate model. [1](#0-0) [3](#0-2) 

Because repayment, withdrawal, borrowing, liquidation, bad-debt cleanup, recapitalization, revenue claims, and parameter updates all depend on the same accrual path, the market becomes permanently frozen rather than merely rejecting one malformed transaction. [11](#0-10) 

The existing regression test explicitly verifies that the affected market has no repayment or withdrawal path after the overflow. [12](#0-11) 

This permanently freezes suppliers’ assets and prevents liquidation or repayment of outstanding debt, satisfying the permanent-freezing impact class. [13](#0-12) [1](#0-0) 

### Likelihood Explanation

Likelihood is **Medium**: the attacker does not need privileged access, but the market’s decimal and supply-cap configuration must admit a scaled notional large enough that index growth later exceeds `i128::MAX`. [8](#0-7) [14](#0-13) 

The attacker also needs sufficient assets to provide the pool liquidity and collateral supporting sustained high utilization, and the overflow emerges only after interest has compounded. [15](#0-14) 

The checked scenario uses one billion 18-decimal tokens and 98% utilization, but production exploitability depends on the configured caps and token supply rather than on owner privileges. [16](#0-15) 

### Recommendation

Bound total scaled supply and debt so `scaled_amount * maximum_possible_index` remains below `i128::MAX`, rather than clamping only the index after multiplication. [7](#0-6) 

Additionally, make accrual detect an impending total-value overflow before unscaled debt is computed, stop index growth at the largest safe value for the current scaled totals, and leave repayment and liquidation paths operational. [17](#0-16) [6](#0-5) 

A wider internal accumulator can also be used for accrual calculations, provided persisted balances and emitted amounts still have explicitly defined saturation behavior. [18](#0-17) 

### Proof of Concept

Assuming an 18-decimal market whose configured caps admit `1e27` base units and another market whose collateral cap supports the required borrow:

1. The attacker creates a liquidity account and supplies `1_000_000_000 * 10^18` base units of the target asset through `Controller::supply(caller, 0, spoke_id, assets)`. [19](#0-18) 
2. The attacker creates a borrowing account, supplies enough collateral, and calls `Controller::borrow(caller, account_id, borrows, to)` to borrow 98% of that liquidity. [20](#0-19) [21](#0-20) 
3. Interest accrues while utilization remains high.
4. The attacker or any keeper calls `Controller::update_indexes(caller, [hub_asset])`; this invokes pool accrual for the market. [9](#0-8) [3](#0-2) 
5. Once `scaled_borrowed * next_borrow_index` exceeds `i128::MAX`, accrual reverts with `MathOverflow`. [22](#0-21) [23](#0-22) 
6. Subsequent `withdraw` and `repay` calls still execute mandatory accrual first, so they fail with the same error. [1](#0-0) [24](#0-23)

### Citations

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

**File:** contracts/pool/src/interest.rs (L35-53)
```rust
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

**File:** contracts/pool/src/cache/scale.rs (L19-27)
```rust
    pub(crate) fn calculate_utilization(&self) -> Ray {
        if self.supplied == Ray::ZERO {
            return Ray::ZERO;
        }
        let total_borrowed = scaled_to_original(&self.env, self.borrowed, self.borrow_index);
        let total_supplied = scaled_to_original(&self.env, self.supplied, self.supply_index);

        utilization(&self.env, total_borrowed, total_supplied)
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

**File:** contracts/pool/src/lib.rs (L128-193)
```rust
    /// Accrues, mints scaled supply shares and credits cash per entry. The
    /// controller transfers the tokens in before this call. Owner-only.
    #[only_owner]
    fn supply(env: Env, entries: Vec<PoolSupplyEntry>) -> Vec<PoolPositionMutation> {
        ops::run_batch(&env, entries, ops::supply::apply)
    }

    /// Batch-borrows assets and transfers them to `receiver`: accrues
    /// interest, mints scaled debt, debits cash, and enforces max
    /// utilization after each mint. Restricted to the owner; returns one
    /// [`PoolPositionMutation`] per entry.
    #[only_owner]
    fn borrow(
        env: Env,
        receiver: Address,
        entries: Vec<PoolBorrowEntry>,
    ) -> Vec<PoolPositionMutation> {
        ops::run_batch(&env, entries, |env, entry| {
            ops::borrow::apply(env, &receiver, entry)
        })
    }

    /// Burns supply shares and transfers the underlying to `receiver`.
    /// `is_liquidation` skips the max-utilization check and may withhold a
    /// protocol fee. Owner-only; `actual_amount` is gross of that fee.
    #[only_owner]
    fn withdraw(
        env: Env,
        receiver: Address,
        is_liquidation: bool,
        entries: Vec<PoolWithdrawEntry>,
    ) -> Vec<PoolPositionMutation> {
        ops::run_batch(&env, entries, |env, entry| {
            ops::withdraw::apply(env, &receiver, is_liquidation, entry)
        })
    }

    /// Burns scaled debt up to the repay amount, credits cash with the net
    /// repay and refunds overpayment to `payer`. Owner-only.
    #[only_owner]
    fn repay(env: Env, payer: Address, actions: Vec<PoolAction>) -> Vec<PoolPositionMutation> {
        ops::run_batch(&env, actions, |env, action| {
            ops::repay::apply(env, &payer, action)
        })
    }

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
```
