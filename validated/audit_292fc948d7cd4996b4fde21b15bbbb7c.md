### Title
Third-party dust supply silently retargets a victim account to current risk parameters - (File: contracts/controller/src/positions/supply.rs)

### Summary
`supply` accepts a caller-selected `account_id`. For an existing account, the only third-party restriction is that every submitted asset already has a supply position. After accepting the deposit, every supply leg calls `refresh_supply_risk_params` with `RiskRefreshScope::FullTuple`, replacing the position’s stored LTV, liquidation threshold, liquidation bonus, and fee values with the currently listed values. This lets an unprivileged address force a victim’s collateral onto newly configured, less favorable liquidation parameters by supplying dust to an existing position. [1](#0-0) [2](#0-1) [3](#0-2) 

### Finding Description
When `account_id` is nonzero, `load_or_create_account` loads the supplied account and, for `AccountGuard::Supply`, only verifies that the caller-provided `spoke_id` matches the stored account spoke. It does not require the caller to own or control that account. [4](#0-3) 

A separate check permits this third-party path when every requested `HubAssetKey` is already present in `account.supply_positions`. Once that check passes, `process_deposit` merges the measured receipt into the victim’s position. [5](#0-4) [6](#0-5) 

During the merge, the account’s existing position is reloaded and `refresh_supply_risk_params` is invoked unconditionally for the supplied market using `RiskRefreshScope::FullTuple`. The resulting mutated position is then written back through `update_or_remove_supply_position`. [7](#0-6) [8](#0-7) 

This bypasses the account-ownership boundary associated with mutating position risk. Unlike the permissionless `update_account_threshold` flow—which applies the restricted risk refresh only when the resulting account clears the update health-factor floor—third-party supply has no post-refresh solvency requirement. [9](#0-8) 

### Impact Explanation
A victim who supplied an asset under older, more favorable liquidation parameters can have that position silently restamped onto current parameters by any third party. If the current parameters have a lower liquidation threshold or otherwise reduce liquidation-weighted collateral, the dust deposit can push the account below HF 1 even though the victim did not authorize a risk refresh.

The attacker can then invoke `liquidate(liquidator=attacker, account_id=victim, debt_payments=..., seize_mode=Transfer)` on the newly liquidatable account and obtain discounted collateral. This is a theft-of-user-funds condition caused by a caller-selected `account_id` redirecting an unauthorized state mutation to another user’s object. [10](#0-9) [11](#0-10) 

### Likelihood Explanation
The attacker needs:

- The victim to have an existing supply position in a listed market.
- The market’s currently listed `FullTuple` risk values to be less protective than the victim’s stored values.
- A positive amount of that asset sufficient to pass measured receipt validation.
- The refreshed position to produce HF < 1.

No ownership, delegate grant, compromised key, contract privilege, malicious route, or oracle manipulation is required. The attacker controls the victim’s `account_id`, asset, and dust amount in the ordinary `supply` call. [12](#0-11) [2](#0-1) 

### Recommendation
Do not let an unauthorized third-party supply refresh the victim’s stored risk tuple.

Concretely:

- In `process_deposit` or `merge_supply_leg`, preserve the existing position’s stored LTV, liquidation threshold, bonus, and fees when the caller is neither the account owner nor an active delegate.
- Alternatively, route the refresh through the same safe logic used by `update_account_threshold`, including the post-refresh health-factor floor.
- Keep third-party deposits limited to measured-share and cash accounting only.
- Add a regression test where governance changes an asset’s liquidation parameters, a stranger supplies one unit to a victim’s existing position, and the stranger is unable to force a liquidation.

### Proof of Concept
```text
Initial state:
1. Victim owns account V.
2. V has an existing supply position in asset A.
3. A's listed liquidation threshold or related liquidation tuple is changed
   to less favorable values.
4. V remains healthy under its stored tuple, but would have HF < 1 under the
   currently listed tuple.

Attack:
5. Attacker acquires 1 base unit of A.
6. Attacker calls:

   controller.supply(
       caller = attacker,
       account_id = V,
       spoke_id = V.spoke_id,
       assets = [(HubAssetKey { hub_id: A.hub_id, asset: A }, 1)]
   )

7. The authorization check passes because A is already present in V's
   supply_positions.
8. merge_supply_leg invokes refresh_supply_risk_params(..., FullTuple),
   overwriting V's stored risk tuple for A.
9. The refreshed liquidation-weighted collateral produces HF < 1.
10. Attacker calls:

    controller.liquidate(
        liquidator = attacker,
        account_id = V,
        debt_payments = planned_debt_repayments,
        seize_mode = SeizeMode::Transfer
    )

11. Attacker repays the selected debt and receives the bonus-discounted
    collateral.
```

The decisive issue is not the receipt of dust; it is that the accepted `account_id` selects a foreign object whose immutable ownership check is replaced by an “existing asset slot” check, while the subsequent merge still performs a full ownership-sensitive risk-parameter update. [13](#0-12) [14](#0-13)

### Citations

**File:** contracts/controller/src/positions/supply.rs (L40-63)
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

**File:** contracts/controller/src/positions/supply.rs (L76-96)
```rust
/// Restricts third parties to existing supply positions. New accounts are
/// exempt because the caller becomes their owner.
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

**File:** contracts/controller/src/positions/supply.rs (L275-299)
```rust
pub(crate) fn merge_supply_leg(
    env: &Env,
    account: &mut Account,
    action: &PoolAction,
    result: &PoolPositionMutation,
    cache: &mut Context,
) {
    let hub_asset = &action.hub_asset;
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
```

**File:** contracts/controller/src/positions/supply.rs (L314-324)
```rust
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

**File:** contracts/controller/src/account.rs (L98-111)
```rust
    let account = storage::get_account(env, account_id);
    match guard {
        AccountGuard::Supply => require_spoke_match(env, &account, spoke_id),
        AccountGuard::Migrate => {
            require_owner_or_delegate(env, account_id, caller, &account.owner);
            require_spoke_match(env, &account, spoke_id);
        }
        AccountGuard::Multiply => {
            require_owner_or_delegate(env, account_id, caller, &account.owner);
            require_spoke_match(env, &account, spoke_id);
            assert_with_error!(env, account.mode == mode, GenericError::AccountModeMismatch);
        }
    }
    (account_id, account)
```

**File:** contracts/controller/src/lib.rs (L382-388)
```rust
    /// Refreshes supply LTV snapshots. With `has_risks`, also refreshes gated
    /// liquidation parameters and requires a final health factor of at least
    /// 1.05 WAD. Permissionless; requires caller authorization.
    #[when_not_paused]
    fn update_account_threshold(env: Env, caller: Address, has_risks: bool, account_ids: Vec<u64>) {
        risk::params::update_account_threshold(&env, caller, has_risks, account_ids);
    }
```

**File:** contracts/controller/src/positions/liquidation/mod.rs (L36-55)
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
```

**File:** contracts/controller/src/positions/liquidation/mod.rs (L68-94)
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
```
