### Title
Bad-debt cleanup leaves floor-clamped supply shares that can drain subsequent deposits - ([File: contracts/pool/src/interest.rs])

### Summary
When a bad-debt write-down would reduce a market's `supply_index` below `SUPPLY_INDEX_FLOOR_RAW`, `apply_bad_debt_to_supply_index` clamps the index to the floor without burning or otherwise sanitizing the surviving supply shares. [1](#0-0)  The remaining shares therefore retain a positive floored claim even when the cleanup consumed all pool cash, and a later deposit can provide the liquidity needed to pay that stale claim. [2](#0-1) 

### Finding Description
`clean_bad_debt` is permissionless and, after the insolvency and dust gates pass, calls `execute_bad_debt_cleanup`. [3](#0-2)  Cleanup serializes the borrower's remaining supply and debt positions, exits their spoke usage, calls `pool_seize_positions_call`, persists usage, and deletes the account. [4](#0-3) 

On the pool side, `apply_bad_debt_to_supply_index` caps the written-down debt at total supplied value and computes the proportional index reduction. [5](#0-4)  It then writes `new_supply_index.max(SUPPLY_INDEX_FLOOR_RAW)`, which silently keeps the index positive even when the correct socialized index would be zero. [6](#0-5) 

Withdrawals resolve user claims by unscaling supply shares at the current `supply_index`. [7](#0-6)  Because all surviving shares retain at least `1/1000` of their index value at the floor, a complete wipeout leaves a positive claim instead of zeroing it. [8](#0-7)  The unit test demonstrates that this residual is masked only while cash is zero: after a fresh deposit equal to the stranded claim, total obligations exceed cash, and the old account withdraws exactly the new deposit. [9](#0-8) 

The reachable sequence is `supply` to create shares, accrual/price movement into eligible bad debt, permissionless `clean_bad_debt`, a third-party or attacker-controlled `supply`, and finally `withdraw` using the withdraw-all sentinel. [10](#0-9)  `process_supply` accepts a new account and calls `process_deposit`, while `process_withdraw` treats a zero amount as withdraw-all. [11](#0-10) [12](#0-11) 

### Impact Explanation
A wiped-out supplier retains an unbacked claim that can consume the next depositor's tokens. [13](#0-12)  This is theft of user funds and creates a pool whose recorded supply obligations exceed its token cash, so the market is insolvent after the residual claim is paid. [13](#0-12) 

A holder can also transfer the position NFT carrying the stranded supply position to another account before a victim replenishes the market. [14](#0-13)  The pool's own regression test labels this residual behavior as draining fresh cash without a supply guard. [15](#0-14) 

### Likelihood Explanation
The trigger requires a bad-debt cleanup severe enough to reduce total supplied value to zero or below the supply-index floor. [1](#0-0)  Permissionless cleanup requires debt to exceed collateral and the remaining collateral to be at or below the protocol dust threshold. [3](#0-2)  Once that state occurs, no privileged action is needed; `clean_bad_debt`, `supply`, and `withdraw` are all callable by ordinary authenticated users. [10](#0-9) 

The exploit does not depend on oracle dishonesty or an external route; it uses the pool's own floor-clamped index and measured withdrawal accounting. [1](#0-0) [7](#0-6) 

### Recommendation
When `remaining` is zero, write the supply index to zero or explicitly burn/normalize all surviving supply shares instead of clamping the index to `SUPPLY_INDEX_FLOOR_RAW`. [16](#0-15)  Alternatively, block new supply while the floor-clamped market still has outstanding shares, and require an explicit recapitalization path that reconciles those shares before deposits resume. [17](#0-16)  Add a regression test asserting that a complete bad-debt wipeout leaves no withdrawable residual before new liquidity is accepted. [18](#0-17) 

### Proof of Concept
The existing unit test constructs a market with `alice_scaled = 1000 * RAY` and equal debt, then applies the bad-debt write-down and burns the debt. [19](#0-18)  The resulting `supply_index` is clamped to `SUPPLY_INDEX_FLOOR_RAW`, while Alice's unscaled supply remains positive and pool cash is zero. [20](#0-19) 

The test then credits Bob's fresh deposit equal to Alice's stranded claim, after which total owed exceeds cash. [21](#0-20)  Alice resolves a withdraw-all request and receives exactly Bob's deposit, leaving insufficient cash for Bob's honest claim. [22](#0-21)

### Citations

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

**File:** contracts/pool/tests/interest.rs (L430-492)
```rust
#[test]
fn test_raw_cache_seizure_residual_would_drain_fresh_cash_without_supply_guard() {
    let t = TestSetup::new();
    t.as_contract(|| {
        let alice_scaled_raw = 1_000 * RAY;
        let borrowed_scaled_raw = 1_000 * RAY;
        let mut cache = t.fresh_cache(PoolStateRaw {
            supplied: alice_scaled_raw,
            borrowed: borrowed_scaled_raw,
            revenue: 0,
            borrow_index: RAY,
            supply_index: RAY,
            last_timestamp: 0,
            cash: 0,
        });
        let alice_scaled = Ray::from(alice_scaled_raw);
        let borrow_scaled = Ray::from(borrowed_scaled_raw);

        let bad_debt = cache.unscale_borrow_ceil_ray(borrow_scaled);
        apply_bad_debt_to_supply_index(&mut cache, bad_debt);
        cache.burn_debt(borrow_scaled);

        assert_eq!(
            cache.supply_index().raw(),
            SUPPLY_INDEX_FLOOR_RAW,
            "seize wipeout clamps supply_index UP to RAY/1000, leaving unburned shares a residual"
        );

        let alice_stranded = cache.unscale_supply_floor(alice_scaled);
        assert!(alice_stranded > 0, "wiped survivor keeps a stranded claim");
        assert_eq!(
            cache.cash(),
            0,
            "empty market: claim masked by require_reserves"
        );

        let deposit = alice_stranded;
        let bob_scaled = cache.calculate_scaled_supply(deposit);
        cache.mint_supply(bob_scaled);
        cache.credit_cash(deposit);

        let total_owed = cache.unscale_supply_floor(cache.supplied());
        assert!(
            total_owed > cache.cash(),
            "post-deposit books insolvent: owed {} > cash {}",
            total_owed,
            cache.cash()
        );

        let (burn, gross) = cache.resolve_withdrawal(i128::MAX, alice_scaled);
        cache.require_reserves(gross);
        cache.burn_supply(burn);
        cache.debit_cash(gross);

        assert!(gross > 0, "wiped position pays out real cash");
        assert_eq!(gross, deposit, "Alice extracts exactly Bob's fresh deposit");

        let bob_claim = cache.unscale_supply_floor(bob_scaled);
        assert!(
            cache.cash() < bob_claim,
            "cash {} cannot cover Bob's honest claim {}: fresh depositor lost funds",
            cache.cash(),
            bob_claim
```

**File:** contracts/controller/src/positions/liquidation/mod.rs (L195-243)
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
    let mut cache = Context::new(env);
    let account = storage::get_account(env, account_id);

    assert_with_error!(
        env,
        !account.borrow_positions.is_empty(),
        CollateralError::DebtPositionNotFound
    );

    let totals = risk::calculate_account_risk_totals(
        env,
        &mut cache,
        &account.supply_positions,
        &account.borrow_positions,
    );

    let admits = match gate {
        BadDebtGate::DustCapped => {
            is_socializable_bad_debt(totals.total_debt, totals.total_collateral)
        }
        BadDebtGate::InsolventOnly => totals.total_debt > totals.total_collateral,
    };
    assert_with_error!(env, admits, CollateralError::CannotCleanBadDebt);

    bad_debt::execute_bad_debt_cleanup(env, &mut cache, account_id, &account, &totals);
}

/// Socializes insolvent debt when remaining collateral is at or below the dust cap.
pub(crate) fn clean_bad_debt_standalone(env: &Env, account_id: u64) {
    socialize_bad_debt(env, account_id, BadDebtGate::DustCapped);
}
```

**File:** contracts/controller/src/positions/liquidation/bad_debt.rs (L21-60)
```rust
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

    cache.persist_spoke_usage();

    CleanBadDebtEvent {
        account_id,
        total_borrow_usd_wad: totals.total_debt.raw(),
        total_collateral_usd_wad: totals.total_collateral.raw(),
    }
    .publish(env);

    remove_account_and_burn_nft(env, account_id);
```

**File:** contracts/pool/src/cache/scale.rs (L94-105)
```rust
    /// Resolves a withdrawal request into (shares burned, gross asset amount).
    ///
    /// Caps against `pos_scaled` so the user cannot withdraw more than held.
    pub(crate) fn resolve_withdrawal(&self, amount: i128, pos_scaled: Ray) -> (Ray, i128) {
        resolve_withdrawal(
            &self.env,
            amount,
            pos_scaled,
            self.supply_index,
            self.params.asset_decimals,
        )
    }
```

**File:** contracts/controller/src/lib.rs (L94-164)
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

**File:** contracts/controller/src/lib.rs (L445-455)
```rust
    /// Returns supply and debt positions keyed by hub asset, or empty maps
    /// if the account does not exist.
    fn get_account_positions(
        env: Env,
        account_id: u64,
    ) -> (
        Map<HubAssetKey, AccountPositionRaw>,
        Map<HubAssetKey, DebtPositionRaw>,
    ) {
        views::get_account_positions(&env, account_id)
    }
```

**File:** contracts/controller/src/positions/supply.rs (L40-73)
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

    finalize_position_flow(
        env,
        acct_id,
        &account,
        &mut cache,
        PositionSides::Supply,
        false,
    );
    acct_id
```

**File:** contracts/controller/src/positions/supply.rs (L140-199)
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

    finalize_position_flow(
        env,
        account_id,
        &account,
        &mut cache,
        PositionSides::Supply,
        true,
    );
    paid
}

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
    }
```
