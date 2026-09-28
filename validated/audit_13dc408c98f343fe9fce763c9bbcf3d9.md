### Title
Accrual-time RAY value overflow can permanently freeze a saturated market - ([File: common/src/rates/index.rs])

### Summary
A buffer-overflow analogue exists as a fixed-point `i128` overflow during interest accrual: when scaled debt grows large enough that `borrowed * borrow_index / RAY` exceeds the RAY value domain, `calculate_supplier_rewards` panics before the borrow-index cap can protect the market. [1](#0-0)  Every pool mutation first runs `global_sync`, so once this boundary is crossed the same accrual path executes before repay, withdraw, borrow, liquidation settlement, `update_indexes`, and cleanup-adjacent pool legs. [2](#0-1) [3](#0-2) 

### Finding Description
The accrual step computes `old_total_debt = borrowed * old_borrow_index` and `new_total_debt = borrowed * new_borrow_index`; `Ray::mul` is exact-widened internally but still returns `i128`, so an economically representable debt can overflow only when its accrued value crosses the i128/RAY ceiling. [4](#0-3) [5](#0-4)  `update_borrow_index` caps the index at `MAX_BORROW_INDEX_RAY`, but that cap is applied to the index value, not to `borrowed * index`, so the total-debt multiplication can still overflow before or at the capped index. [6](#0-5)  The public reachable route is through controller verbs that call owner-gated pool legs: `supply`, `borrow`, `withdraw`, `repay`, and `update_indexes` all enter pool paths that load a synced market before accounting. [7](#0-6) [8](#0-7) 

### Impact Explanation
Impact: Medium, permanent freezing of funds for the affected `(hub_id, asset)` market. Once `new_total_debt` overflows, `global_sync` panics on every subsequent mutation, so suppliers cannot withdraw, borrowers cannot repay, liquidators cannot settle through the pool, and `update_indexes` cannot advance the market past the failing chunk. [9](#0-8) [4](#0-3)  The panic is not a clean reject of an oversized input; it is state-dependent and persists because the stored `borrowed` and index remain above the safe product. [2](#0-1) 

### Likelihood Explanation
Likelihood is low-to-moderate: an attacker cannot trigger it in one transaction from an empty market, but an unprivileged user can supply and borrow through `Controller::supply`/`Controller::borrow`, and any later public call that accrues the market can become the final push once utilization and time drive the accrued debt value over the ceiling. [10](#0-9) [11](#0-10)  The practical precondition is whale-scale liquidity plus sustained high utilization, but caps can be configured up to the asset-domain maximum and the overflow is determined by stored scaled debt times index rather than by admin misconfiguration. [12](#0-11) [13](#0-12) 

### Recommendation
Bound the accrual input before multiplying: in `accrue_step`/`calculate_supplier_rewards`, compare `borrowed` against `i128::MAX / new_borrow_index` in widened arithmetic and either clamp growth to the largest index whose total-debt value still fits `i128`, or fail into an explicit market-halted state that still permits unwind-only paths such as repay, withdraw, liquidation, and `clean_bad_debt`. [1](#0-0) [2](#0-1)  At minimum, make `update_borrow_index` enforce the product ceiling jointly with `borrowed`, since capping the index alone does not bound the value multiplication that actually overflows. [6](#0-5) 

### Proof of Concept
1. An unprivileged account supplies a large collateral position, then calls `borrow` on a high-decimal market until scaled borrowed shares are near the RAY-domain ceiling; this uses the public `Controller::borrow` path into owner-gated `pool.borrow`. [14](#0-13) [15](#0-14) 
2. Keep utilization high so the borrow index keeps compounding; each public mutation calls `ops::load_leg`/`synced_market`, which runs `interest::global_sync` before the requested verb. [2](#0-1) [9](#0-8) 
3. On the accrual where `borrowed.mul(new_borrow_index)` exceeds `i128::MAX`, `calculate_supplier_rewards` panics with `MathOverflow`; the transaction aborts before committing the accrual. [4](#0-3) [16](#0-15) 
4. Retrying `repay`, `withdraw`, `update_indexes`, or liquidation-driven pool legs re-enters the same `global_sync` first and hits the same multiplication, leaving the market permanently bricked rather than merely rejecting one bad call. [17](#0-16) [18](#0-17)

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

**File:** common/src/math/fp_core.rs (L138-143)
```rust
    let (x256, y256, d256) = to_i256_operands(env, x, y, d);
    x256.mul(&y256)
        .add(&I256::from_i128(env, half))
        .div(&d256)
        .to_i128()
}
```

**File:** contracts/controller/src/lib.rs (L38-44)
```rust
use common::errors::SpokeError;
use common::types::{
    AccountAttributes, AccountPositionRaw, DebtPositionRaw, HubAssetKey, InterestRateModel,
    LiquidationEstimate, MarketIndexRaw, MarketIndexView, MarketParamsRaw, PositionLimits,
    PositionManagerConfig, PositionMode, SeizeMode, SpokeAssetArgs, SpokeAssetConfig, SpokeConfig,
    SpokeUsageRaw,
};
```

**File:** contracts/controller/src/lib.rs (L94-134)
```rust
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
```

**File:** contracts/pool/src/lib.rs (L128-180)
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
```

**File:** common/src/rates/scaling.rs (L54-66)
```rust
pub fn calculate_scaled_borrow(env: &Env, amount: i128, decimals: u32, borrow_index: Ray) -> Ray {
    Ray::from_asset(env, amount, decimals).div_ceil(env, borrow_index)
}

/// Converts an asset-unit `amount` to a scaled borrow `Ray` using floor
/// rounding relative to `borrow_index`.
pub fn calculate_scaled_borrow_floor(
    env: &Env,
    amount: i128,
    decimals: u32,
    borrow_index: Ray,
) -> Ray {
    Ray::from_asset(env, amount, decimals).div_floor(env, borrow_index)
```

**File:** contracts/pool/src/ops/repay.rs (L40-60)
```rust
pub(crate) fn accounting(env: &Env, action: &PoolAction) -> RepayOutcome {
    let (mut cache, position) = ops::load_leg(env, action);
    let amount = action.amount;

    let (burned, overpayment) = cache.resolve_repay(amount, position);
    let net_repay = amount
        .checked_sub(overpayment)
        .unwrap_or_else(|| panic_with_error!(env, GenericError::MathOverflow));
    assert_with_error!(
        env,
        net_repay == 0 || burned.raw() > 0,
        GenericError::RepayRoundsToZeroShares
    );

    let position = position.checked_sub(env, burned);
    cache.burn_debt(burned);

    cache.credit_cash(net_repay);

    let snapshot = cache.commit();
    let mutation = cache.position_mutation(position, net_repay);
```

**File:** contracts/pool/src/ops/withdraw.rs (L57-83)
```rust
pub(crate) fn accounting(
    env: &Env,
    is_liquidation: bool,
    entry: &PoolWithdrawEntry,
) -> WithdrawOutcome {
    require_nonneg_amount(env, entry.protocol_fee);
    let (mut cache, position) = ops::load_leg(env, &entry.action);

    let (burned, gross_amount) = resolve_close_or_partial(&cache, entry.action.amount, position);
    // Burn first: `protocol_fee_shares` caps the fee mint at `i128::MAX - supplied`.
    let remaining = burn_position(env, &mut cache, position, burned);
    let net_transfer = withhold_liquidation_fee(
        env,
        &mut cache,
        gross_amount,
        is_liquidation,
        entry.protocol_fee,
    );

    // A footprint-only close must not add a utilization gate to same-market
    // net settlement: it burns no shares and moves no cash.
    let empty_close = position.raw() == 0 && entry.action.amount == i128::MAX;
    gate_and_debit(env, &mut cache, net_transfer, is_liquidation || empty_close);

    let snapshot = cache.commit();
    let mutation = cache.position_mutation(remaining, gross_amount);
    WithdrawOutcome {
```
