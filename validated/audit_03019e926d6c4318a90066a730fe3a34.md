### Title
Flash-position callback can execute a ready governance update while stale spoke-asset parameters remain cached - (File: contracts/controller/src/strategies/flash_position.rs)

### Summary

`flash_position` loads spoke-asset configuration into an invocation-local `Context`, invokes an attacker-controlled receiver, and then continues depositing collateral and checking solvency with that same cache. Because `Governance::execute` permits anyone to execute a ready operation, the receiver can atomically change the spoke-asset configuration after the controller has cached it. The outer transaction then stamps and validates the new position using the obsolete LTV and liquidation parameters.

### Finding Description

`Context::cached_spoke_asset` retains the first successful `SpokeAssetConfig` read for a spoke asset for the remainder of the invocation. [1](#0-0)  During `flash_position`, the controller validates the requested collateral before entering the guarded callback. [2](#0-1)  The same `cache` is reused after `execute_flash_position` returns to deposit the received collateral. [3](#0-2) 

Governance execution is permissionless when `executor` is `None`, provided the referenced operation is ready. [4](#0-3)  A receiver can therefore execute a ready spoke-asset risk update during the callback. Afterward, `process_deposit`, `restamp_listed_supply_ltv`, and the final risk checks all consume the stale cached listing rather than the newly committed configuration. [5](#0-4) [6](#0-5) 

This is the smart-contract analog of the reported stale-cache bug: a later state transition invalidates the assumptions under which a reused cache was populated, but the cache pointer-equivalent is not invalidated.

### Impact Explanation

An attacker can open a leveraged account under a governance-superseded collateral configuration. For example, a ready operation that lowers collateral LTV or changes liquidation terms can be executed in the callback, while the resulting position is still stamped and checked with the old, more favorable parameters.

The attacker can then retain debt that would fail under the current configuration and later exit through withdrawal or liquidation economics, leaving the pool with undercollateralized debt or bad debt. This can result in theft of pool funds or protocol insolvency rather than merely bypassing an administrative timing preference.

### Likelihood Explanation

Exploitation requires:

- A ready, non-expired governance operation that tightens the selected collateral’s risk configuration.
- An attacker-controlled Wasm flash receiver implementing `execute_flash_position`.
- Sufficient flash-minted debt and callback-supplied collateral to satisfy the stale cached checks.

No privileged authentication is required during the attack because the attacker calls `Controller::flash_position` directly and the receiver calls `Governance::execute` with `executor = None`. [7](#0-6) [4](#0-3) 

### Recommendation

Invalidate spoke configuration after any external callback, or reload it before post-callback deposits and solvency checks. In particular:

- Call `cache.reset_spoke_context()` after `invoke_receiver` returns and before `process_deposit`.
- Recheck every collateral and debt asset’s `paused`, `frozen`, `is_collateralizable`, `is_borrowable`, LTV, liquidation threshold, bonus, and fees against storage after the callback.
- Persist only position parameters loaded after the callback, not parameters cached before it.
- Add a regression test in which `execute_flash_position` executes a governance update and the outer flow must reject collateral that was valid before the callback.

### Proof of Concept

Conceptual transaction:

1. Governance schedules an operation that changes collateral `C` from `loan_to_value = 0.80` to `loan_to_value = 0.20` or makes it non-collateralizable.
2. Attacker deploys a receiver contract implementing `execute_flash_position`.
3. Attacker calls:

```text
Controller::flash_position(
    caller = attacker,
    account_id = 0,
    spoke_id = S,
    mode = PositionMode::Multiply,
    debt = D,
    amount = debt_amount,
    receiver = attacker_receiver,
    data = encoded_ready_operation,
    collaterals = [(C, min_collateral)],
    refund_assets = [],
)
```

4. Before the callback, the controller validates `C` and caches its old configuration. [2](#0-1) 
5. Inside `execute_flash_position`, the receiver invokes:

```text
Governance::execute(
    executor = None,
    target = controller,
    function = scheduled_spoke_asset_update_function,
    args = scheduled_args_for_C,
    predecessor = scheduled_predecessor,
    salt = scheduled_salt,
)
```

6. The governance operation commits the tighter configuration for `C`.
7. The receiver returns the required amount of `C` to the controller.
8. The outer call deposits `C` and performs solvency checks through the same `Context`, whose `spoke_assets` map still contains the pre-callback listing. [1](#0-0) [8](#0-7) 
9. The resulting account is stamped with obsolete favorable risk parameters and remains usable for borrowing or liquidation under those stale terms until a separate refresh occurs. [9](#0-8)

### Citations

**File:** contracts/controller/src/context.rs (L191-204)
```rust
    /// Returns the listed spoke asset config, caching successful reads only.
    pub(crate) fn cached_spoke_asset(
        &mut self,
        spoke_id: u32,
        hub_asset: &HubAssetKey,
    ) -> Option<SpokeAssetConfig> {
        self.ensure_spoke_context(spoke_id);
        if let Some(cfg) = self.spoke_assets.get(hub_asset.clone()) {
            return Some(cfg);
        }
        let loaded = storage::get_spoke_asset(&self.env, spoke_id, hub_asset)?;
        self.spoke_assets.set(hub_asset.clone(), loaded.clone());
        Some(loaded)
    }
```

**File:** contracts/controller/src/strategies/flash_position.rs (L103-154)
```rust
    validate_collaterals(env, &mut cache, &account, collaterals);
    validate_refund_assets(
        env,
        &mut cache,
        account.spoke_id,
        debt.hub_id,
        collaterals,
        refund_assets,
    );

    let mut extra_assets = vec![env, debt.asset.clone()];
    for (hub_asset, _) in collaterals.iter() {
        extra_assets.push_back(hub_asset.asset.clone());
    }
    prefetch_strategy_prices(&mut cache, &account, &extra_assets);

    // Guard both forwarding and the callback: token hooks can reenter first.
    let (amount_received, collateral_before, refund_before) =
        storage::with_flash_guard(env, || {
            let amount_received =
                mint_and_forward(env, &mut account, debt, amount, receiver, &mut cache);
            // Baselines exclude funding and forwarding; count callback receipts only.
            let collateral_before = snapshot_balances(
                env,
                &controller,
                collaterals.iter().map(|(hub_asset, _)| hub_asset.asset),
            );
            let refund_before = snapshot_balances(env, &controller, refund_assets.iter());
            invoke_receiver(
                env,
                receiver,
                caller,
                account_id,
                &debt.asset,
                amount,
                amount_received,
                &controller,
                data,
            );
            (amount_received, collateral_before, refund_before)
        });

    let deposits = collect_collateral_deposits(env, &controller, collaterals, &collateral_before);
    process_deposit(env, &controller, &mut account, &deposits, &mut cache);

    refund_listed_assets(env, caller, refund_assets, &refund_before);

    // Check before and after finalization: its LTV refresh can prune zero-scaled
    // supply, and persistence removes empty accounts.
    require_flash_position_still_open(env, &account, debt);
    strategy_finalize(env, account_id, &mut account, &mut cache);
    require_flash_position_still_open(env, &account, debt);
```

**File:** contracts/governance/src/api.rs (L53-67)
```rust
    /// Executes a ready, non-expired scheduled op against `target` (not this
    /// contract). If `executor` is `Some`, requires that address to auth and
    /// hold `EXECUTOR_ROLE`; if `None`, no executor role check (anyone may
    /// drive execution of a ready op). Clears scheduled state on success.
    fn execute(
        env: Env,
        executor: Option<Address>,
        target: Address,
        function: Symbol,
        args: Vec<Val>,
        predecessor: BytesN<32>,
        salt: BytesN<32>,
    ) -> Val {
        lifecycle::execute(&env, executor, target, function, args, predecessor, salt)
    }
```

**File:** contracts/controller/src/positions/mod.rs (L81-90)
```rust
/// Restamps listed supply LTVs, then checks collateral coverage, health factor,
/// and minimum borrow collateral. Returns whether any LTV changed.
pub(crate) fn enforce_post_pool_solvency(
    env: &Env,
    cache: &mut Context,
    account: &mut Account,
) -> bool {
    let restamped = risk::restamp_listed_supply_ltv(cache, account);
    validation::require_post_pool_risk_gates(env, cache, account);
    restamped
```

**File:** contracts/controller/src/risk/params.rs (L42-63)
```rust
/// Refreshes stored LTV snapshots in memory for listed supply assets, skipping
/// unlisted assets. Returns whether any position changed.
pub(crate) fn restamp_listed_supply_ltv(cache: &mut Context, account: &mut Account) -> bool {
    let mut changed = false;
    let keys = account.supply_positions.keys();
    for hub_asset in keys.iter() {
        let Some(listed) = cache.cached_spoke_asset(account.spoke_id, &hub_asset) else {
            continue;
        };
        let config: AssetConfig = (&listed).into();
        let Some(raw) = account.supply_positions.get(hub_asset.clone()) else {
            continue;
        };
        let mut position = AccountPosition::from(&raw);
        if position.loan_to_value.raw() == config.loan_to_value.raw() {
            continue;
        }
        position.loan_to_value = config.loan_to_value;
        update_or_remove_supply_position(account, &hub_asset, &position);
        changed = true;
    }
    changed
```

**File:** contracts/controller/src/risk/params.rs (L191-219)
```rust
        let changed = refresh_supply_risk_params(
            env,
            cache,
            &account,
            &hub_asset,
            &mut updated,
            &asset_config,
            scope,
        );
        if !changed {
            continue;
        }

        any_changed = true;
        update_or_remove_supply_position(&mut account, &hub_asset, &updated);

        let market_index = cache.cached_market_index(&hub_asset);
        cache.record_supply_position_update(
            events::PositionAction::ParamUpd,
            &hub_asset,
            market_index.supply_index.raw(),
            0,
            &updated,
        );
    }

    if any_changed {
        storage::set_supply_positions(env, account_id, &account.supply_positions);
    }
```

**File:** contracts/controller/src/lib.rs (L182-216)
```rust
    /// Mints `amount` of `debt` without a flash fee, forwards measured receipts
    /// and invokes the Wasm receiver's `execute_flash_position` callback.
    /// `collaterals` sets minimum controller-balance increases to deposit;
    /// listed `refund_assets` balance increases return to the caller.
    /// Returns the solvent account's id; `account_id = 0` creates it. An existing
    /// account requires owner or delegate authorization and a matching mode.
    #[when_not_paused]
    fn flash_position(
        env: Env,
        caller: Address,
        account_id: u64,
        spoke_id: u32,
        mode: PositionMode,
        debt: HubAssetKey,
        amount: i128,
        receiver: Address,
        data: Bytes,
        collaterals: Vec<(HubAssetKey, i128)>,
        refund_assets: Vec<Address>,
    ) -> u64 {
        strategies::flash_position::process_flash_position(
            &env,
            &caller,
            FlashPositionParams {
                account_id,
                spoke_id,
                mode,
                debt: &debt,
                amount,
                receiver: &receiver,
                data: &data,
                collaterals: &collaterals,
                refund_assets: &refund_assets,
            },
        )
```
