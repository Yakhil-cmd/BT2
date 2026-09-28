### Title
Stale pre-writedown supply index lets suppliers withdraw full claims and concentrate bad debt on remaining suppliers - (`contracts/pool/src/ops/withdraw.rs`)

### Summary
XOXNO Lending has the same stale-valuation bug class: withdrawals are valued from the interest-synced `supply_index`, but loan losses are written into that index only when liquidation or bad-debt cleanup calls `seize_positions`. An unprivileged supplier can therefore withdraw at the pre-loss index after an account becomes insolvent but before socialization executes, draining cash and leaving the remaining suppliers to absorb a larger write-down.

### Finding Description
`Controller::withdraw` authorizes the account owner or delegate, maps a zero withdrawal leg to `WITHDRAW_ALL_SENTINEL`, and submits the position to the pool withdrawal batch. [1](#0-0) [2](#0-1) 

The pool withdrawal path only calls `interest::global_sync`, which accrues time-based interest and does not recognize undercollateralized debt as a loss. [3](#0-2) [4](#0-3) 

The withdrawal is then priced by `resolve_withdrawal` at the current `supply_index`, burns the resulting shares, checks cash, utilization, and nonzero supply, debits cash, and transfers the payout. [5](#0-4) [6](#0-5) 

None of these withdrawal gates revalues debt by collateral coverage or calls `backing_shortfall`; `require_supply_for_debt` rejects only the special case where all supply is gone while debt remains. [7](#0-6) 

Bad debt reaches the supply index only through `seize_positions` on the borrow side, which computes the unpaid debt and calls `apply_bad_debt_to_supply_index`. [8](#0-7) [9](#0-8) 

On the controller side, that write-down happens only after liquidation execution or through the separate bad-debt cleanup path. [10](#0-9) [11](#0-10) 

`get_collateral_amount` has the same stale economic view because it unscales the stored shares by the simulated supply index without accounting for pending bad-debt socialization. [12](#0-11) 

### Impact Explanation
A supplier who exits during the pre-socialization window receives cash priced as though the outstanding debt were still fully collectible. The subsequent `seize_positions` call lowers the market's `supply_index`, so the suppliers who did not exit absorb the departed supplier's share of the loss as well as their own. [8](#0-7) [13](#0-12) 

This can produce direct loss of user funds and, once cash is exhausted, temporarily freeze or permanently impair the remaining suppliers' claims. The existing regression test demonstrates the exact concentration effect: an early supplier recovers at least its pre-crash balance, while the remaining supplier's loss is more than three times the passive case. [14](#0-13) 

### Likelihood Explanation
The prerequisite is a publicly insolvent account and enough pool cash for a supplier to withdraw before a liquidation or cleanup transaction is executed. A supplier needs only call the normal `withdraw` entrypoint on its own account; `withdraw` is not reserved to governance or keepers and does not itself prove that all pending bad debt has been socialized. [15](#0-14) [6](#0-5) 

The race is realistic because bad-debt recognition is transaction-driven rather than automatic at price-report or withdrawal time. Permissionless cleanup exists, but it is a separate call and is gated by the dust-cap path, while larger residual collateral uses the owner-only gate. [16](#0-15) 

### Recommendation
Socialize pending bad debt before permitting ordinary withdrawals from the affected market, or add a market-level pending-loss gate that blocks normal exits until liquidation/cleanup and any required recapitalization have run. At minimum, expose a risk-adjusted withdrawal value and ensure user-facing balances cannot be interpreted as immediately payable claims while a known bad-debt write-down is pending. The key invariant is that no supplier may redeem at a supply index that still treats already-unrecoverable debt as fully collectible.

### Proof of Concept
1. Supplier A and Supplier B supply the same debt asset, and a borrower opens a debt position backed by another collateral asset. [17](#0-16) 
2. The collateral price falls enough to make the borrower insolvent, but no liquidator or cleanup caller has executed yet. [18](#0-17) 
3. Supplier A calls `withdraw` with amount `0` for the debt asset; the controller turns the leg into a full withdrawal and the pool pays it using the pre-writedown `supply_index`. [2](#0-1) [5](#0-4) 
4. A later liquidation or cleanup calls `seize_positions`, burns the debt, and lowers `supply_index`; Supplier B now absorbs the whole remaining write-down and may be unable to recover its full claim. [8](#0-7) [19](#0-18)

### Citations

**File:** contracts/controller/src/positions/supply.rs (L140-158)
```rust
pub(crate) fn process_withdraw(
    env: &Env,
    caller: &Address,
    account_id: u64,
    withdrawals: &Vec<HubPayment>,
    to: Option<Address>,
) -> Vec<HubPayment> {
    validation::require_authorized_caller(env, caller);

    let mut account = storage::get_account(env, account_id);
    require_owner_or_delegate(env, account_id, caller, &account.owner);

    let recipient = to.unwrap_or_else(|| caller.clone());
    let mut cache = Context::new(env);
    require_external_recipient(env, &mut cache, &recipient);
    let aggregated = payments::aggregate_payments(env, withdrawals, payments::ZeroLeg::MeansAll);

    let paid = settle_withdraw(env, &mut account, &recipient, &aggregated, &mut cache);
    let _ = enforce_post_pool_solvency(env, &mut cache, &mut account);
```

**File:** contracts/controller/src/positions/supply.rs (L189-197)
```rust
        let position = get_supply_position_or_panic(env, account, &hub_asset);
        let requested = if amount == 0 {
            WITHDRAW_ALL_SENTINEL
        } else {
            amount
        };
        entries.push_back(PoolWithdrawEntry {
            action: make_pool_action(&position, requested, hub_asset.clone()),
            protocol_fee: 0,
```

**File:** contracts/pool/src/ops/mod.rs (L42-47)
```rust
/// Validates `action.amount ≥ 0`, syncs the market, and returns (cache, scaled position).
pub(crate) fn load_leg(env: &Env, action: &PoolAction) -> (Cache, Ray) {
    require_nonneg_amount(env, action.amount);
    let cache = synced_market(env, &action.hub_asset);
    (cache, Ray::from(action.position.scaled_amount))
}
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

**File:** contracts/pool/src/interest.rs (L73-89)
```rust
pub(crate) fn apply_bad_debt_to_supply_index(cache: &mut Cache, bad_debt: Ray) {
    let total_supplied_value = cache.supplied().mul(cache.env(), cache.supply_index());

    if total_supplied_value == Ray::ZERO {
        return;
    }

    let capped = bad_debt.min(total_supplied_value);
    let remaining = total_supplied_value.checked_sub(cache.env(), capped);

    let reduction_factor = remaining.div_floor(cache.env(), total_supplied_value);
    let new_supply_index = cache
        .supply_index()
        .mul_floor(cache.env(), reduction_factor);

    cache.set_supply_index(new_supply_index.max(Ray::from(SUPPLY_INDEX_FLOOR_RAW)));
}
```

**File:** contracts/pool/src/ops/withdraw.rs (L63-82)
```rust
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
```

**File:** contracts/pool/src/ops/withdraw.rs (L109-118)
```rust
/// Enforces reserve, utilization, and solvency guards, then debits cash for
/// the net transfer. Liquidations and footprint-only closes skip utilization.
fn gate_and_debit(env: &Env, cache: &mut Cache, net_transfer: i128, skip_utilization_check: bool) {
    cache.require_reserves(net_transfer);

    if !skip_utilization_check {
        guards::require_utilization_below_max(env, cache);
    }
    guards::require_supply_for_debt(env, cache);
    cache.debit_cash(net_transfer);
```

**File:** contracts/pool/src/guards.rs (L60-72)
```rust
/// Asset units by which supplier claims exceed cash + debt (0 if solvent).
pub(crate) fn backing_shortfall(cache: &Cache) -> i128 {
    let supplied_claim = cache.unscale_supply_floor(cache.supplied());
    let outstanding_debt = cache.unscale_borrow_ceil(cache.borrowed());
    let backing = cache.cash().saturating_add(outstanding_debt);
    supplied_claim.saturating_sub(backing).max(0)
}

/// Panics with `PoolInsolvent` if supplied is zero while borrowed debt is non-zero.
pub(crate) fn require_supply_for_debt(env: &Env, cache: &Cache) {
    if cache.supplied() == Ray::ZERO && cache.borrowed() != Ray::ZERO {
        panic_with_error!(env, CollateralError::PoolInsolvent);
    }
```

**File:** contracts/pool/src/ops/seize.rs (L23-28)
```rust
    match entry.side {
        AccountPositionType::Borrow => {
            let bad_debt = cache.unscale_borrow_ceil_ray(position);
            interest::apply_bad_debt_to_supply_index(&mut cache, bad_debt);
            cache.burn_debt(position);
        }
```

**File:** contracts/controller/src/positions/liquidation/mod.rs (L105-137)
```rust
    let post_totals = risk::calculate_account_risk_totals(
        env,
        &mut cache,
        &account.supply_positions,
        &account.borrow_positions,
    );

    // Event order: LiquidationEvent, liquidated account's UpdatePositionBatchEvent,
    // optional receiver batch, then CleanBadDebtEvent. Cleanup emits no position deltas.
    finalize_position_flow(
        env,
        account_id,
        &account,
        &mut cache,
        PositionSides::Both,
        false,
    );

    if let Some((receiver_id, receiving_account)) = &receiver {
        apply::record_share_credit_updates(env, receiving_account, &seized, &mut cache);
        finalize_position_flow(
            env,
            *receiver_id,
            receiving_account,
            &mut cache,
            PositionSides::Supply,
            false,
        );
    }

    apply::check_bad_debt_after_liquidation(env, &mut cache, account_id, &account, &post_totals);

    receiver.map_or(0, |(id, _)| id)
```

**File:** contracts/controller/src/positions/liquidation/mod.rs (L195-212)
```rust
/// Authorizes permissionless dust-gated cleanup outside flash loans.
pub(crate) fn process_clean_bad_debt(env: &Env, caller: &Address, account_id: u64) {
    caller.require_auth();
    validation::require_not_flash_loaning(env);
    clean_bad_debt_standalone(env, account_id);
}

/// Admission condition for bad-debt socialization.
#[derive(Clone, Copy, PartialEq)]
enum BadDebtGate {
    /// Permissionless: insolvent *and* collateral at or below the dust threshold.
    DustCapped,
    /// Owner-only: insolvent alone, with no cap on the collateral left behind.
    InsolventOnly,
}

/// Requires open debt and the selected insolvency gate, then cleans up the account.
fn socialize_bad_debt(env: &Env, account_id: u64, gate: BadDebtGate) {
```

**File:** contracts/controller/src/views.rs (L51-72)
```rust
/// Returns the account's current supply position amount for `hub_asset` in
/// asset units, or 0 if it holds no such position.
pub(crate) fn collateral_amount_for_hub_asset(
    env: &Env,
    account_id: u64,
    hub_asset: &HubAssetKey,
) -> i128 {
    let Some(position) = storage::try_get_supply_position(env, account_id, hub_asset) else {
        return 0;
    };

    let mut cache = Context::new_view(env);
    let market_index = cache.cached_market_index(hub_asset);
    let decimals = cache.cached_pool_sync_data(hub_asset).params.asset_decimals;

    // Half-up: scaled * supply_index → asset units (same as pool supplied_amount).
    unscale_supply(
        env,
        position.scaled_amount,
        market_index.supply_index,
        decimals,
    )
```

**File:** tests/test-harness/tests/controller/bad_debt_index.rs (L415-424)
```rust
    // Scenario B: identical state, but Bob withdraws before the write-down.
    let mut b = setup();
    b.supply(BOB, "ETH", 75.0);
    b.supply(CAROL, "ETH", 25.0);
    b.supply(ALICE, "USDC", 10.0);
    b.borrow(ALICE, "ETH", 0.003);

    let carol_before_b = b.supply_balance(CAROL, "ETH");
    let bob_before_b = b.supply_balance(BOB, "ETH");
    let bob_wallet_before = b.token_balance(BOB, "ETH");
```

**File:** tests/test-harness/tests/controller/bad_debt_index.rs (L426-451)
```rust
    // The crash is public state. Alice is insolvent from here on, but no
    // write-down has been applied yet.
    b.set_price("USDC", usd_cents(10));
    b.assert_liquidatable(ALICE);

    // Bob exits at the un-written-down index. No gate stops him: the
    // liquidation buffer only guards borrow draws, and `backing_shortfall`
    // still values Alice's uncollateralised debt at face.
    b.withdraw_all(BOB, "ETH");
    let bob_recovered = b.token_balance(BOB, "ETH") - bob_wallet_before;

    b.liquidate(LIQUIDATOR, ALICE, "ETH", 0.001);
    let carol_loss_b = carol_before_b - b.supply_balance(CAROL, "ETH");

    assert!(
        bob_recovered >= bob_before_b,
        "Bob exits whole: supplied={:.9} recovered={:.9}",
        bob_before_b,
        bob_recovered
    );
    assert!(
        carol_loss_b > carol_loss_a,
        "dodging must push loss onto Carol: A={:.9} B={:.9}",
        carol_loss_a,
        carol_loss_b
    );
```
