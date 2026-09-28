### Title
Unprivileged third-party supply can restamp a victim’s liquidation parameters and force liquidation - (File: contracts/controller/src/positions/supply.rs)

### Summary
An attacker can call `supply` on another account and restamp an existing collateral position to the asset’s current full risk configuration, without being the account owner or delegate. This bypasses the `update_account_threshold` health-factor floor and can turn a near-boundary account liquidatable, after which the attacker can seize collateral through `liquidate`.

### Finding Description
`supply` authenticates only `caller`, loads an existing account, and permits a third party to add funds only when every submitted market is already present in `account.supply_positions`. [1](#0-0) [2](#0-1) 

The measured deposit is then merged through `merge_supply_leg`, which calls `refresh_supply_risk_params` with `RiskRefreshScope::FullTuple` on the existing position before writing it back to the account. [3](#0-2) [4](#0-3) 

The dedicated risk-refresh path documents that a full risk update requires the resulting health factor to be at least `1.05`; the third-party `supply` path has no equivalent final-account solvency check. [5](#0-4) 

This is the same authentication-confusion shape as the etcd issue: authorization tied to one fact—the attacker paying an already-held asset—is treated as authority over a different security domain—the victim’s stored liquidation risk parameters.

### Impact Explanation
If governance tightens a collateral’s LTV, liquidation threshold, or related risk tuple while a victim remains solvent under its stored parameters, an attacker can spend the minimum positive amount of that collateral to force the old position onto the new configuration. If the restamped health factor falls below `1`, the attacker can immediately call `liquidate(liquidator = attacker, account_id = victim, debt_payments = ..., seize_mode = Transfer)` and receive discounted collateral. [6](#0-5) 

This permits unauthorized forced liquidation and theft of liquidation bonus/value from users who never authorized the caller to mutate their account’s risk snapshot.

### Likelihood Explanation
The attack is permissionless and costs only a positive amount of a token that the victim already supplies. It requires a prior governance tightening of that collateral’s risk parameters and a victim sufficiently close to the new liquidation boundary, so it is conditional rather than universally exploitable. The normal safeguard for restamping risk exists, making the bypass plausibly reachable in ordinary market-parameter maintenance. [5](#0-4) 

### Recommendation
Do not run `RiskRefreshScope::FullTuple` on an existing position for a caller that is neither the owner nor an active delegate. Either keep the stored risk tuple for third-party top-ups, refresh only non-risk-bearing fields for that caller class, or apply the same post-update health-factor floor used by risk restamping. New positions created for the caller can safely initialize with current configuration.

### Proof of Concept
1. Victim account `A` owns NFT account `42`, has an existing supply position in `X`, has debt, and is solvent only under the stored risk tuple.
2. Governance subsequently tightens `X`’s collateral parameters enough that `A`’s health factor would be below `1` under the current tuple.
3. Attacker calls:
   `supply(caller = attacker, account_id = 42, spoke_id = A.spoke_id, assets = [(X_key, 1)])`.
4. The third-party check passes because `X_key` is already present in `A.supply_positions`; it does not establish owner or delegate authority. [2](#0-1) 
5. `merge_supply_leg` restamps the existing position through `refresh_supply_risk_params(..., RiskRefreshScope::FullTuple)`, and the mutated position is stored. [7](#0-6) [4](#0-3) 
6. The attacker calls `liquidate(caller = attacker, account_id = 42, debt_payments = [(D_key, repayment)], seize_mode = SeizeMode::Transfer)` and receives victim collateral at the liquidation bonus once the restamped health factor is below `1`. [8](#0-7)

### Citations

**File:** contracts/controller/src/positions/supply.rs (L47-63)
```rust
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

**File:** contracts/controller/src/positions/supply.rs (L86-94)
```rust
    if account_id != 0
        && !account::is_owner_or_delegate(env, resolved_account_id, caller, &account.owner)
    {
        for (hub_asset, _) in aggregated.iter() {
            assert_with_error!(
                env,
                account.supply_positions.contains_key(hub_asset.clone()),
                GenericError::NotAuthorized
            );
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

**File:** contracts/controller/src/positions/supply.rs (L323-323)
```rust
    update_or_remove_supply_position(account, hub_asset, &position);
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
