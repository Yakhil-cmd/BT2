### Title
Unchecked RAY debt multiplication can permanently freeze an active market - (File: common/src/rates/index.rs)

### Summary
At sufficiently large scaled debt and accrued borrow index, interest accrual panics while calculating `borrowed * borrow_index`, before the intended borrow-index cap can protect the market. Because every pool operation synchronizes and accrues the market first, this makes repayment, withdrawal, liquidation, and index updates permanently revert.

### Finding Description
`update_indexes`, `supply`, `borrow`, `withdraw`, `repay`, liquidation settlement, and other pool legs all load a synchronized market through `ops::synced_market`, which calls `interest::global_sync` before the operation-specific logic. [1](#0-0) [2](#0-1) 

During accrual, `calculate_supplier_rewards` multiplies the market-wide scaled debt by both the old and new borrow indexes using `Ray::mul`. [3](#0-2)  The result is a fixed-point `i128`; a very large scaled debt can overflow this multiplication even though `new_borrow_index` remains below `MAX_BORROW_INDEX_RAY`. [4](#0-3) 

The index cap is therefore applied to the index itself but does not bound the market-wide scaled debt multiplied by that index. [4](#0-3) [5](#0-4)  Once accrued time pushes the product past `i128::MAX`, the accrual panics before state can be committed, so the stale `last_timestamp` remains and every later operation hits the same overflow. [2](#0-1) 

### Impact Explanation
This causes permanent freezing of funds in the affected market rather than a single failed transaction. [1](#0-0) [6](#0-5)  Suppliers cannot withdraw because withdrawal first calls `load_leg` and synchronizes the market. [7](#0-6)  Borrowers cannot repay because repayment follows the same synchronization path before burning debt. [8](#0-7)  Liquidations cannot complete because controller liquidation invokes the pool repayment path. [9](#0-8) 

The repository’s long-horizon test demonstrates this terminal state: after the overflow occurs, `update_indexes`, `withdraw`, and `repay` all fail with `MATH_OVERFLOW`, while the stored borrow index is still below `MAX_BORROW_INDEX_RAY`. [10](#0-9) 

### Likelihood Explanation
An unprivileged attacker can establish the precondition through ordinary `supply` and `borrow` calls by creating a very large scaled debt position and keeping utilization high. [11](#0-10) [12](#0-11)  The attack requires a high-decimal or otherwise high-unit-supply listed asset, enough collateral to support the borrow, and accrued interest over time, so it is less direct than an immediate malformed-input crash. [13](#0-12) [14](#0-13)  The existing test reaches the overflow at 98% utilization and confirms that the resulting freeze is not hypothetical. [15](#0-14) 

### Recommendation
Bound the product before multiplication: reject or clamp accrual when `borrowed` exceeds `i128::MAX / new_borrow_index`, or perform debt valuation in `I256` and apply an explicit protocol-level cap before converting back to `i128`. [5](#0-4)  The cap must cover the market-wide value calculation, not only the index value returned by `update_borrow_index`. [4](#0-3)  Regression coverage should assert that a market approaching this boundary remains repayable, withdrawable, liquidatable, and accrual-capable. [10](#0-9) 

### Proof of Concept
1. In a listed high-decimal market, an attacker supplies a very large token amount through controller `supply(caller, account_id, spoke_id, assets)`, minting a corresponding scaled supply position. [11](#0-10) 
2. Using separately supplied collateral, the attacker borrows nearly all liquidity through `borrow(caller, account_id, borrows, to)`, producing a very large market-wide scaled `borrowed` value. [12](#0-11) [16](#0-15) 
3. Keep utilization high and allow enough ledger time to accrue; each accrual chunk calls `accrue_step`, which computes old and new total debt with `borrowed.mul(index)`. [17](#0-16) [5](#0-4) 
4. Once `borrowed * borrow_index` exceeds `i128::MAX`, `update_indexes` reverts with `MathOverflow` before `mark_accrued` can persist progress. [6](#0-5) [18](#0-17) 
5. Subsequent `repay`, `withdraw`, and liquidation attempts all synchronize the same market first and revert identically, permanently freezing the market’s funds. [19](#0-18) [20](#0-19)

### Citations

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

**File:** contracts/pool/src/interest.rs (L20-48)
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

**File:** common/src/rates/index.rs (L73-87)
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

```

**File:** contracts/pool/src/ops/withdraw.rs (L57-65)
```rust
pub(crate) fn accounting(
    env: &Env,
    is_liquidation: bool,
    entry: &PoolWithdrawEntry,
) -> WithdrawOutcome {
    require_nonneg_amount(env, entry.protocol_fee);
    let (mut cache, position) = ops::load_leg(env, &entry.action);

    let (burned, gross_amount) = resolve_close_or_partial(&cache, entry.action.amount, position);
```

**File:** contracts/pool/src/ops/repay.rs (L40-45)
```rust
pub(crate) fn accounting(env: &Env, action: &PoolAction) -> RepayOutcome {
    let (mut cache, position) = ops::load_leg(env, action);
    let amount = action.amount;

    let (burned, overpayment) = cache.resolve_repay(amount, position);
    let net_repay = amount
```

**File:** contracts/controller/src/positions/liquidation/apply.rs (L75-85)
```rust
        let position: DebtPosition =
            (&expect_invariant(env, account.borrow_positions.get(entry.hub_asset.clone()))).into();
        actions.push_back(make_pool_action(&position, received, entry.hub_asset));
    }
    apply_repay_batch(
        env,
        account,
        liquidator,
        events::PositionAction::LiqRepay,
        &actions,
        cache,
```

**File:** tests/test-harness/tests/controller/large_positions_and_long_horizons.rs (L329-356)
```rust
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

**File:** contracts/controller/src/positions/supply.rs (L40-64)
```rust
pub(crate) fn process_supply(
    env: &Env,
    caller: &Address,
    account_id: u64,
    spoke_id: u32,
    assets: &Vec<HubPayment>,
) -> u64 {
    validation::require_authorized_caller(env, caller);
    let aggregated = payments::aggregate_positive_payments(env, assets);
    let mut cache = Context::new(env);

    let (acct_id, mut account) = account::load_or_create_account(
        env,
        caller,
        account_id,
        spoke_id,
        PositionMode::Normal,
        account::AccountGuard::Supply,
        &mut cache,
    );

    require_third_party_existing_supply(env, account_id, acct_id, caller, &account, &aggregated);

    process_deposit(env, caller, &mut account, &aggregated, &mut cache);

```

**File:** contracts/controller/src/positions/debt.rs (L33-60)
```rust
pub(crate) fn process_borrow(
    env: &Env,
    caller: &Address,
    account_id: u64,
    borrows: &Vec<HubPayment>,
    to: Option<Address>,
) {
    validation::require_authorized_caller(env, caller);

    let mut account = storage::get_account(env, account_id);
    require_owner_or_delegate(env, account_id, caller, &account.owner);

    let recipient = to.unwrap_or_else(|| caller.clone());
    let mut cache = Context::new(env);
    require_external_recipient(env, &mut cache, &recipient);
    let aggregated = payments::aggregate_positive_payments(env, borrows);

    validate_position_entry_gates(
        env,
        &account,
        &aggregated,
        &mut cache,
        AccountPositionType::Borrow,
    );
    settle_borrow(env, &mut account, &recipient, &aggregated, &mut cache);

    let restamped = enforce_post_pool_solvency(env, &mut cache, &mut account);
    let sides = if restamped {
```

**File:** common/src/rates/scaling.rs (L52-56)
```rust
/// Converts an asset-unit `amount` to a scaled borrow `Ray` using ceiling
/// rounding relative to `borrow_index`.
pub fn calculate_scaled_borrow(env: &Env, amount: i128, decimals: u32, borrow_index: Ray) -> Ray {
    Ray::from_asset(env, amount, decimals).div_ceil(env, borrow_index)
}
```

**File:** contracts/pool/src/ops/borrow.rs (L63-79)
```rust
pub(crate) fn mint_debt(env: &Env, cache: &mut Cache, position: &mut Ray, amount: i128) {
    require_positive_amount(env, amount);
    cache.require_reserves(amount);
    guards::require_liquidation_buffer(env, cache, amount);

    let minted = cache.calculate_scaled_borrow(amount);

    assert_with_error!(
        env,
        minted.raw() > 0,
        GenericError::BorrowRoundsToZeroShares
    );

    *position = position.checked_add(env, minted);
    cache.mint_debt(minted);
    guards::require_utilization_below_max(env, cache);
}
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
