### Title
Suppliers can withdraw before bad-debt realization and concentrate losses on remaining suppliers - (File: `contracts/pool/src/ops/withdraw.rs`)

### Summary
XOXNO Lending contains the same loss-timing vulnerability class: bad debt remains valued at face until liquidation or cleanup socializes it, while suppliers can exit at the unimpaired supply index beforehand. An unprivileged supplier who observes a newly insolvent borrower can call `withdraw` before anyone calls `liquidate` or `clean_bad_debt`, recover the pre-loss value of their shares, and leave the later index write-down to the remaining suppliers. [1](#0-0) 

### Finding Description
Supply positions are represented as scaled shares valued through the market supply index, while bad debt is applied later by reducing that index. [2](#0-1) 

The controller exposes a normal `withdraw` entrypoint in which zero requests a full withdrawal. [3](#0-2)  Withdrawal authorization only requires the caller to be the account owner or delegate, after which the request is forwarded to the pool. [4](#0-3)  A zero amount is converted to `WITHDRAW_ALL_SENTINEL`, so the supplier can exit the entire position in one call. [5](#0-4) 

Pool withdrawal accounting resolves and burns supply shares at the current index, checks reserves, utilization, and the no-debt-without-supply shape, and then debits cash. [6](#0-5)  The withdrawal gate does not inspect pending insolvent accounts or write down bad debt before paying the exit. [7](#0-6) 

Bad debt is only written into the supply index through the borrow-side seize path used by liquidation or bad-debt cleanup. [8](#0-7)  `liquidate` is callable by an arbitrary authorized liquidator, and `clean_bad_debt` is likewise externally reachable, but neither must run before an unrelated supplier exits. [9](#0-8) 

The repository already contains a regression-style test demonstrating this sequence: after a public collateral-price crash makes Alice insolvent, Bob withdraws before the write-down and recovers at least his full pre-loss balance. [10](#0-9)  The subsequent liquidation increases Carol’s loss relative to the scenario where Bob did not exit. [11](#0-10)  In the tested 75%/25% supply split, Carol’s loss is amplified by more than three times and expectedly approaches four times. [12](#0-11) 

### Impact Explanation
This is a theft/loss-shifting impact: the exiting supplier receives cash backed partly by debt that is already economically impaired, while remaining suppliers later absorb the full write-down through a reduced supply index. [13](#0-12)  The issue can drain available cash before loss realization and leave remaining suppliers with materially lower redemption value or a temporarily under-collateralized market. [14](#0-13) 

The severity is Medium because the attack requires an externally caused insolvency and sufficient pool cash for the early withdrawal, but it permits an unprivileged supplier to avoid its pro-rata share of a known pending loss. [15](#0-14) 

### Likelihood Explanation
The trigger is observable on-chain: a price update or accumulated interest makes an account unhealthy before liquidation or cleanup executes. [16](#0-15)  A supplier can then submit `withdraw(caller, account_id, [(debt_asset_key, 0)], to)` without interacting with the insolvent account. [17](#0-16) 

No privileged role, leaked key, malformed parameter, or oracle manipulation is required. [3](#0-2)  The main constraint is timing: the withdrawal must execute before a liquidation or cleanup realizes the residual bad debt. [18](#0-17) 

### Recommendation
Realize eligible bad debt before allowing normal supply withdrawals, or make withdrawal valuation account for known impaired debt rather than valuing all outstanding debt at face. One approach is a permissionless `realize_bad_debt(account_id)` step that withdrawal executes for accounts known to be socializable, or a controller-maintained pending-loss accounting mechanism that discounts affected supply before exits. [19](#0-18) 

At minimum, the withdrawal path should run a market-level pending-bad-debt gate or explicitly document and enforce a loss-realization ordering so that suppliers cannot race ahead of socialization. [7](#0-6) 

### Proof of Concept
The existing test `supplier_can_exit_ahead_of_bad_debt_writedown` provides a direct proof:

```rust
// Initial state:
// Bob supplies 75 ETH, Carol supplies 25 ETH.
// Alice supplies 10 USDC and borrows 0.003 ETH.

// Alice becomes insolvent after the USDC price falls.
set_price("USDC", usd_cents(10));

// Bob exits all ETH supply before liquidation.
controller.withdraw(
    bob,
    bob_account_id,
    vec![(eth_hub_asset, 0)],
    Some(bob),
);

// A liquidator later repays part of Alice's ETH debt.
controller.liquidate(
    liquidator,
    alice_account_id,
    vec![(eth_hub_asset, 0_001_units)],
    SeizeMode::Transfer,
);

// Residual ETH bad debt is now written down only against
// Carol's remaining ETH supply shares.
```

The test sets up identical passive and early-exit scenarios using Bob, Carol, and Alice. [20](#0-19)  It confirms that Alice is insolvent before Bob exits and that Bob receives at least his original supply balance. [21](#0-20)  It then confirms that the later liquidation leaves Carol with a larger loss than in the no-exit baseline. [22](#0-21)

### Citations

**File:** tests/test-harness/tests/controller/bad_debt_index.rs (L396-400)
```rust
/// Bad debt is written down only when a liquidation or cleanup call runs, and
/// `backing_shortfall` counts the unrecoverable debt at face value until then.
/// A supplier can exit at the pre-write-down index and leave the loss on the
/// suppliers who stay. Runs the same crash with Bob passive and with Bob
/// exiting first, and compares Carol's loss.
```

**File:** tests/test-harness/tests/controller/bad_debt_index.rs (L402-461)
```rust
fn supplier_can_exit_ahead_of_bad_debt_writedown() {
    // Scenario A: nobody dodges. Bob 75%, Carol 25% of the ETH supply.
    let mut a = setup();
    a.supply(BOB, "ETH", 75.0);
    a.supply(CAROL, "ETH", 25.0);
    a.supply(ALICE, "USDC", 10.0);
    a.borrow(ALICE, "ETH", 0.003);

    let carol_before_a = a.supply_balance(CAROL, "ETH");
    a.set_price("USDC", usd_cents(10));
    a.liquidate(LIQUIDATOR, ALICE, "ETH", 0.001);
    let carol_loss_a = carol_before_a - a.supply_balance(CAROL, "ETH");

    // Scenario B: identical state, but Bob withdraws before the write-down.
    let mut b = setup();
    b.supply(BOB, "ETH", 75.0);
    b.supply(CAROL, "ETH", 25.0);
    b.supply(ALICE, "USDC", 10.0);
    b.borrow(ALICE, "ETH", 0.003);

    let carol_before_b = b.supply_balance(CAROL, "ETH");
    let bob_before_b = b.supply_balance(BOB, "ETH");
    let bob_wallet_before = b.token_balance(BOB, "ETH");

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

    // Carol holds 25% of supply, so passing the whole loss to her is ~4x.
    let amplification = carol_loss_b / carol_loss_a;
    assert!(
        amplification > 3.0,
        "expected ~4x concentration onto the remaining supplier, got {:.3}x \
         (A={:.9} B={:.9})",
        amplification,
        carol_loss_a,
        carol_loss_b
```

**File:** contracts/pool/src/interest.rs (L68-74)
```rust
/// Socializes `bad_debt` by reducing the supply index (capped at total supply value).
///
/// Used when seizing unpaid debt: remaining supplier claims shrink pro-rata.
/// No-op when total supplied value is zero. Floors the resulting index at
/// [`SUPPLY_INDEX_FLOOR_RAW`] to avoid a zero index.
pub(crate) fn apply_bad_debt_to_supply_index(cache: &mut Cache, bad_debt: Ray) {
    let total_supplied_value = cache.supplied().mul(cache.env(), cache.supply_index());
```

**File:** contracts/pool/src/interest.rs (L80-89)
```rust
    let capped = bad_debt.min(total_supplied_value);
    let remaining = total_supplied_value.checked_sub(cache.env(), capped);

    let reduction_factor = remaining.div_floor(cache.env(), total_supplied_value);
    let new_supply_index = cache
        .supply_index()
        .mul_floor(cache.env(), reduction_factor);

    cache.set_supply_index(new_supply_index.max(Ray::from(SUPPLY_INDEX_FLOOR_RAW)));
}
```

**File:** contracts/controller/src/lib.rs (L117-127)
```rust
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
```

**File:** contracts/controller/src/lib.rs (L136-165)
```rust
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
    }
```

**File:** contracts/controller/src/positions/supply.rs (L147-158)
```rust
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

**File:** contracts/controller/src/positions/supply.rs (L171-198)
```rust
/// Enforces exit flags and withdraws the batch, treating zero as withdraw-all.
/// Returns each asset's actual pool payout.
fn settle_withdraw(
    env: &Env,
    account: &mut Account,
    recipient: &Address,
    aggregated: &AggregatedPayments,
    cache: &mut Context,
) -> Vec<HubPayment> {
    let mut entries: Vec<PoolWithdrawEntry> = Vec::new(env);
    for (hub_asset, amount) in aggregated.iter() {
        enforce_spoke_asset_flags(
            env,
            cache,
            account.spoke_id,
            &hub_asset,
            FreezePolicy::AllowOnExit,
        );
        let position = get_supply_position_or_panic(env, account, &hub_asset);
        let requested = if amount == 0 {
            WITHDRAW_ALL_SENTINEL
        } else {
            amount
        };
        entries.push_back(PoolWithdrawEntry {
            action: make_pool_action(&position, requested, hub_asset.clone()),
            protocol_fee: 0,
        });
```

**File:** contracts/pool/src/ops/withdraw.rs (L63-80)
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

```

**File:** contracts/pool/src/ops/withdraw.rs (L109-119)
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

**File:** contracts/controller/src/positions/liquidation/bad_debt.rs (L14-49)
```rust
pub(crate) fn execute_bad_debt_cleanup(
    env: &Env,
    cache: &mut Context,
    account_id: u64,
    account: &Account,
    totals: &AccountRiskTotals,
) {
    let mut entries: Vec<PoolSeizeEntry> = Vec::new(env);
    for (hub_asset, position) in iter_typed_positions(&account.supply_positions) {
        cache.apply_spoke_exit(
            account.spoke_id,
            UsageSide::Supply,
            &hub_asset,
            position.scaled_amount,
        );
        entries.push_back(PoolSeizeEntry {
            hub_asset,
            side: AccountPositionType::Deposit,
            position: (&position).into(),
        });
    }
    for (hub_asset, position) in iter_debt_positions(&account.borrow_positions) {
        cache.apply_spoke_exit(
            account.spoke_id,
            UsageSide::Borrow,
            &hub_asset,
            position.scaled_amount,
        );
        entries.push_back(PoolSeizeEntry {
            hub_asset,
            side: AccountPositionType::Borrow,
            position: (&position).into(),
        });
    }
    let pool_addr = cache.cached_pool_address();
    pool_seize_positions_call(env, &pool_addr, &entries);
```
