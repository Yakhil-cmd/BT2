### Title
Third-party collateral top-up can force a protected risk-parameter restamp and make a victim liquidatable - (File: contracts/controller/src/positions/supply.rs)

### Summary
An unprivileged address can abuse the permissionless third-party top-up path in `controller::supply` to refresh a victim collateral position’s cached LTV, liquidation threshold, and liquidation bonus without satisfying the `update_account_threshold` health-factor floor. After governance tightens a listed collateral’s risk parameters, the attacker supplies a minimal amount to an asset the victim already holds, causing `merge_supply_leg` to restamp the position with `RiskRefreshScope::FullTuple` before crediting the deposit. [1](#0-0) [2](#0-1) 

### Finding Description
`controller::supply` intentionally allows a stranger to add funds only to an existing supply position, but that path still reaches the same `process_deposit` and `merge_supply_leg` logic used by the account owner. [3](#0-2) [4](#0-3)   
`merge_supply_leg` calls `refresh_supply_risk_params(..., RiskRefreshScope::FullTuple)` on the victim’s existing position, so the attacker-controlled deposit updates the cached risk tuple rather than merely increasing collateral. [2](#0-1)   
This bypasses the dedicated permissionless maintenance entrypoint’s safety rule: with `has_risks = true`, `update_account_threshold` requires a final health factor of at least 1.05 WAD, preventing keepers from restamping an account directly into liquidation. [5](#0-4) [6](#0-5) 

### Impact Explanation
If governance lowers a collateral’s liquidation threshold or otherwise worsens its risk tuple while the victim still has the old cached tuple, the attacker can force the new tuple onto the victim and then call `liquidate` once the recalculated health factor is below 1. [7](#0-6)   
The liquidation path is permissionless and pays the liquidator collateral at the protocol-defined bonus, so the forced restamp can convert a previously non-liquidatable account into a profitable seizure. [8](#0-7) 

### Likelihood Explanation
The attack requires a legitimate risk-parameter tightening or equivalent listing change that lowers the victim’s cached liquidation threshold enough to produce `HF < 1`; it does not work while the relevant spoke-asset listing is paused or frozen, because the deposit path enforces entry flags. [9](#0-8)   
When those conditions hold, the attacker only needs to donate one positive measured unit to a collateral position the victim already has, making the trigger inexpensive and reachable by any address. [1](#0-0) 

### Recommendation
Do not run `RiskRefreshScope::FullTuple` for a supply leg when `caller` is neither the account owner nor an active delegate, or preserve the existing liquidation-risk tuple on third-party top-ups and refresh only the LTV/accounting fields needed for the deposit. [4](#0-3) [10](#0-9)   
Alternatively, apply the same post-restamp health-factor floor used by `update_account_threshold(..., has_risks = true, ...)` to any third-party supply that would change liquidation parameters. [5](#0-4) 

### Proof of Concept
1. Victim owns account `A` with an existing supply position in `HubAssetKey { hub_id: H, asset: C }`, whose stored risk tuple still contains the old, higher liquidation threshold. [11](#0-10) 
2. Governance executes a valid `edit_asset_in_spoke` that lowers `C`’s liquidation threshold enough that victim `A` is unhealthy under the current parameters but still healthy under the cached parameters.
3. Attacker calls `controller::supply(caller = attacker, account_id = A, spoke_id = A.spoke_id, assets = [(HubAssetKey { hub_id: H, asset: C }, 1)])`; the third-party check passes because `A` already holds `C`, and `merge_supply_leg` restamps the position’s full risk tuple. [11](#0-10) [10](#0-9) 
4. With `A` now below `HF = 1`, attacker calls `controller::liquidate(liquidator = attacker, account_id = A, debt_payments = [(HubAssetKey { hub_id: H, asset: D }, amount)], seize_mode = SeizeMode::Transfer)`, repays debt, and receives bonus-discounted collateral. [7](#0-6) [12](#0-11)

### Citations

**File:** contracts/controller/src/positions/supply.rs (L38-47)
```rust
/// Supplies collateral, creating an account when `account_id` is zero.
/// Third parties may only add to existing supply positions. Returns the account id.
pub(crate) fn process_supply(
    env: &Env,
    caller: &Address,
    account_id: u64,
    spoke_id: u32,
    assets: &Vec<HubPayment>,
) -> u64 {
    validation::require_authorized_caller(env, caller);
```

**File:** contracts/controller/src/positions/supply.rs (L61-96)
```rust
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
}

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

**File:** contracts/controller/src/positions/supply.rs (L283-296)
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
```

**File:** contracts/controller/src/lib.rs (L136-150)
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

**File:** docs/reference/endpoints.md (L37-40)
```markdown
| `update_indexes(caller: Address, assets: Vec<HubAssetKey>)` | None | gated | Accrue specified markets. |
| `claim_revenue(caller: Address, assets: Vec<HubAssetKey>) -> Vec<i128>` | None | gated | Pay only configured accumulator; return controller receipts. |
| `update_account_threshold(caller: Address, has_risks: bool, account_ids: Vec<u64>)` | None | gated | Refresh LTV; optional risk refresh requires final HF >= 1.05. |
| `recapitalize(payer: Address, hub_asset: HubAssetKey, amount: i128) -> i128` | None | open | Measured backing injection; refund surplus; return amount applied. |
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

**File:** contracts/controller/src/positions/liquidation/mod.rs (L80-93)
```rust
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
```

**File:** contracts/controller/src/positions/mod.rs (L186-227)
```rust
/// Requires an active hub, an active spoke listing, and neither pause nor
/// freeze. Returns the config for the supply or borrow permission check.
fn require_listed_unhalted_config(
    env: &Env,
    cache: &mut Context,
    spoke_id: u32,
    hub_asset: &HubAssetKey,
) -> AssetConfig {
    cache.require_hub_active(hub_asset.hub_id);
    let asset_config = cache.require_listed_active_config(spoke_id, hub_asset);
    enforce_spoke_asset_flags(env, cache, spoke_id, hub_asset, FreezePolicy::BlockOnEntry);
    asset_config
}

/// Requires an active, unhalted listing that permits borrowing.
pub(crate) fn require_can_borrow(
    env: &Env,
    cache: &mut Context,
    spoke_id: u32,
    hub_asset: &HubAssetKey,
) {
    let asset_config = require_listed_unhalted_config(env, cache, spoke_id, hub_asset);
    assert_with_error!(
        env,
        asset_config.is_borrowable,
        CollateralError::AssetNotBorrowable
    );
}

/// Requires an active, unhalted listing that permits collateral supply.
pub(crate) fn require_can_supply(
    env: &Env,
    cache: &mut Context,
    spoke_id: u32,
    hub_asset: &HubAssetKey,
) {
    let asset_config = require_listed_unhalted_config(env, cache, spoke_id, hub_asset);
    assert_with_error!(
        env,
        asset_config.is_collateralizable,
        CollateralError::NotCollateral
    );
```
