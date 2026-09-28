### Title
Third-party supply can restamp a victim's collateral risk parameters and force liquidation - (File: contracts/controller/src/positions/supply.rs)

### Summary
`supply` authenticates the caller, but for an existing account it only requires the caller to top up supply positions that already exist rather than be the owner/delegate. [1](#0-0) [2](#0-1)  The deposit path then runs `merge_supply_leg`, which reloads the current spoke-asset config and calls `refresh_supply_risk_params` on the victim's existing collateral position before committing it. [3](#0-2) [4](#0-3)  Unlike the public threshold-refresh path, this flow has no `has_risks` final-health-factor buffer and no post-supply solvency gate before `finalize_position_flow`. [5](#0-4) [6](#0-5) 

### Finding Description
A third party cannot add a new collateral asset to someone else's account, but it can supply dust to an existing collateral leg and thereby restamp that leg's cached LTV/threshold from the current `SpokeAssetConfig`. [7](#0-6) [8](#0-7)  If governance has tightened the asset's risk parameters since the victim's position snapshot was written, a `1`-unit top-up can reduce the victim's stored collateral factors even though the supplied value is negligible. [9](#0-8)  The attacker can then call the permissionless `liquidate`, which authenticates only the liquidator, applies measured repayments, and seizes collateral according to the computed plan. [10](#0-9) [11](#0-10) 

### Impact Explanation
This can convert a still-solvent cached position into a liquidatable one without the account owner/delegate authorizing the risk refresh, after which the attacker captures the liquidation bonus by repaying debt and seizing collateral. [8](#0-7) [12](#0-11)  The qualifying impact is theft of user funds through forced liquidation caused by an unauthorized state-changing refresh, not merely disclosure or a keeper convenience. [13](#0-12) [14](#0-13) 

### Likelihood Explanation
The path is fully permissionless once a victim has debt plus an existing supply position in a spoke asset whose risk config later tightens; the attacker needs only enough balance for a measured positive dust transfer and must satisfy entry flags/caps for that existing asset. [1](#0-0) [15](#0-14)  It is narrower than a universal seize bug because it depends on stale cached risk parameters and a near-boundary account, but it bypasses the safer explicit refresh model that otherwise guards threshold restamping. [5](#0-4) [16](#0-15) 

### Recommendation
For non-owner/non-delegate top-ups into an existing account, preserve the position's cached risk tuple and skip `refresh_supply_risk_params`, or require owner/delegate authorization before any restamp. [13](#0-12) [8](#0-7)  If third-party restamping is intended, apply the same post-refresh safety invariant as `update_account_threshold` with `has_risks`, including a final health-factor buffer before the new parameters become liquidation-effective. [5](#0-4) 

### Proof of Concept
1. Victim has account `A` in `spoke_id` with existing supply in `hub_asset C` and outstanding debt; `C`'s cached LTV/threshold predates a governance tightening. [2](#0-1) 
2. Attacker calls `supply(attacker, A, spoke_id_of_A, vec![(C, 1)])`; `require_third_party_existing_supply` passes because `C` is already present, `transfer_amount_measured` pulls the dust to the pool, and `merge_supply_leg` restamps `A`'s `C` position from the current config. [7](#0-6) [3](#0-2) [9](#0-8) 
3. With the tightened tuple, `is_liquidatable(A)`/`get_health_factor(A)` now reflect HF below `1` even though the added collateral value is negligible. [17](#0-16) [4](#0-3) 
4. Attacker calls `liquidate(attacker, A, debt_payments, SeizeMode::Transfer)`; `liquidator.require_auth()` passes, the plan repays debt legs and seizes the now-undercollateralized collateral at bonus to the attacker. [10](#0-9) [12](#0-11)

### Citations

**File:** contracts/controller/src/positions/supply.rs (L40-72)
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
```

**File:** contracts/controller/src/positions/supply.rs (L78-97)
```rust
fn require_third_party_existing_supply(
    env: &Env,
    account_id: u64,
    resolved_account_id: u64,
    caller: &Address,
    account: &Account,
    aggregated: &AggregatedPayments,
) {
    if account_id != 0
        && !account::is_owner_or_delegate(env, resolved_account_id, caller, &account.owner)
    {
        for (hub_asset, _) in aggregated.iter() {
            assert_with_error!(
                env,
                account.supply_positions.contains_key(hub_asset.clone()),
                GenericError::NotAuthorized
            );
        }
    }
}
```

**File:** contracts/controller/src/positions/supply.rs (L107-135)
```rust
    validate_position_entry_gates(
        env,
        account,
        aggregated,
        cache,
        AccountPositionType::Deposit,
    );
    let pool_addr = cache.cached_pool_address();
    let mut entries: Vec<PoolSupplyEntry> = Vec::new(env);
    for (hub_asset, amount_in) in aggregated.iter() {
        let asset_config: AssetConfig = cache.require_spoke_asset(account.spoke_id, &hub_asset);
        let received = payments::transfer_amount_measured(
            env,
            &hub_asset.asset,
            caller,
            &pool_addr,
            amount_in,
            GenericError::AmountMustBePositive,
        );
        let position = account.get_or_create_supply_position(&hub_asset, &asset_config);
        entries.push_back(PoolSupplyEntry {
            action: make_pool_action(&position, received, hub_asset.clone()),
        });
    }

    let results = pool_supply_call(env, &pool_addr, &entries);
    for_each_leg(env, &entries, &results, |entry, result| {
        merge_supply_leg(env, account, &entry.action, &result, cache);
    });
```

**File:** contracts/controller/src/positions/supply.rs (L283-324)
```rust
    let asset_config: AssetConfig = cache.require_spoke_asset(account.spoke_id, hub_asset);

    let mut position = account.get_or_create_supply_position(hub_asset, &asset_config);
    let old_scaled = position.scaled_amount;

    refresh_supply_risk_params(
        env,
        cache,
        account,
        hub_asset,
        &mut position,
        &asset_config,
        RiskRefreshScope::FullTuple,
    );

    let outcome = LegOutcome::from(result);
    position.scaled_amount = outcome.new_scaled;

    apply_leg_usage(
        env,
        cache,
        account.spoke_id,
        UsageSide::Supply,
        hub_asset,
        LegDirection::Entry {
            asset_decimals: result.asset_decimals,
        },
        old_scaled,
        &outcome,
    );

    cache.put_market_index(hub_asset, &outcome.market_index);
    cache.record_supply_position_update(
        events::PositionAction::Supply,
        hub_asset,
        outcome.market_index.supply_index,
        action.amount,
        &position,
    );

    update_or_remove_supply_position(account, hub_asset, &position);
}
```

**File:** contracts/controller/src/lib.rs (L382-387)
```rust
    /// Refreshes supply LTV snapshots. With `has_risks`, also refreshes gated
    /// liquidation parameters and requires a final health factor of at least
    /// 1.05 WAD. Permissionless; requires caller authorization.
    #[when_not_paused]
    fn update_account_threshold(env: Env, caller: Address, has_risks: bool, account_ids: Vec<u64>) {
        risk::params::update_account_threshold(&env, caller, has_risks, account_ids);
```

**File:** contracts/controller/src/lib.rs (L415-423)
```rust
    fn is_liquidatable(env: Env, account_id: u64) -> bool {
        views::can_be_liquidated(&env, account_id)
    }

    /// Returns liquidation-weighted collateral divided by debt, in WAD;
    /// `i128::MAX` if the account has no debt or does not exist.
    fn get_health_factor(env: Env, account_id: u64) -> i128 {
        views::health_factor(&env, account_id)
    }
```

**File:** contracts/controller/src/positions/liquidation/mod.rs (L36-58)
```rust
pub(crate) fn process_liquidation(
    env: &Env,
    liquidator: &Address,
    account_id: u64,
    debt_payments: &Vec<HubPayment>,
    seize_mode: SeizeMode,
) -> u64 {
    liquidator.require_auth();
    validation::require_not_flash_loaning(env);

    let mut account = storage::get_account(env, account_id);

    let mut cache = Context::new(env);

    require_non_empty_payments(env, debt_payments);

    // Reject an unusable receiver before moving tokens.
    let mut receiver = resolve_seize_receiver(
        env, liquidator, account_id, &account, seize_mode, &mut cache,
    );

    // Share payment normalization and positivity checks with the estimate view.
    let liquidation_plan = plan::build_liquidation_plan(env, &account, debt_payments, &mut cache);
```

**File:** contracts/controller/src/positions/liquidation/mod.rs (L68-103)
```rust
    let received_usd = apply::apply_liquidation_repayments(
        env,
        liquidator,
        &mut account,
        &result.repaid,
        offered.as_ref(),
        &mut cache,
    );

    // Under-delivering debt tokens must reduce the collateral awarded.
    let repay_usd = math::sum_repaid_usd(env, &result.repaid);
    let seized = math::scale_seizures_to_received(env, &result.seized, received_usd, repay_usd);
    match &mut receiver {
        None => {
            apply::apply_liquidation_seizures(env, liquidator, &mut account, &seized, &mut cache)
        }
        Some((_, receiving_account)) => {
            apply::require_credit_position_limit(env, receiving_account, &seized, &mut cache);
            apply::apply_liquidation_share_credit(
                env,
                &mut account,
                receiving_account,
                &seized,
                &mut cache,
            );
        }
    }

    // Report measured receipt value, capped per planned repayment leg.
    LiquidationEvent {
        liquidator: liquidator.clone(),
        account_id,
        repaid_usd_wad: received_usd.raw(),
        bonus_bps: result.bonus_bps,
    }
    .publish(env);
```
