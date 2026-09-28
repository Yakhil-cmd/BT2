### Title
Controller cannot recover accidental or undeclared token balances - (File: contracts/controller/src/payments.rs)

### Summary
Any unprivileged address can transfer a Soroban token directly to the controller, but the controller has no sweep or generic token-withdrawal path that can return the pre-existing balance. Controller refund logic intentionally returns only positive balance deltas recorded during an operation, leaving previously transferred tokens permanently under contract custody.

### Finding Description
`refund_controller_balance_delta` computes `current_balance - balance_before` and transfers only that positive delta back to the caller, explicitly preserving the pre-existing controller balance. [1](#0-0) 

`flash_position` snapshots the controller’s balances before invoking the receiver and later refunds only listed assets’ positive deltas, so an undeclared token pushed during the callback—or an earlier unrelated deposit—is not returned. [2](#0-1) [3](#0-2) 

`borrow` and `withdraw` reject the controller and pool as recipients specifically because funds sent to the controller would remain unclaimed by balance-delta accounting. [4](#0-3) 

The public controller surface supplies, borrows, withdraws, repays, liquidates, executes flash paths and recapitalizes markets, but exposes no generic `sweep`, `rescue`, or owner-callable token withdrawal for an unrelated balance. [5](#0-4) [6](#0-5) [7](#0-6) 

### Impact Explanation
Tokens transferred directly to the controller are permanently frozen because no reachable controller operation recognizes or spends that pre-existing balance. This affects listed and unlisted assets, including the native XLM Stellar Asset Contract token; the loss is borne by the sender, while the protocol cannot recover the assets without a privileged upgrade path outside the accepted attack surface. [1](#0-0) [4](#0-3) 

### Likelihood Explanation
The path only requires an ordinary token `transfer(sender, controller, amount)` and does not need a vulnerable market or privileged authorization. It can also occur when a flash-position receiver returns an asset that was not included in `refund_assets`; that callback balance remains in the controller rather than being refunded. [8](#0-7) [9](#0-8) 

### Recommendation
Add a bounded recovery mechanism for stranded controller balances, ideally restricted to amounts not attributable to active flow accounting—for example, an owner-approved `sweep(asset, recipient, amount)` operation that rejects transfers of balances needed by an in-flight callback. Alternatively, require every callback-returned asset to be declared and sweep all positive unclaimed residuals at transaction end. [1](#0-0) [9](#0-8) 

### Proof of Concept
1. Let `controller` be the deployed controller address and `asset` be any Soroban token, including the XLM SAC.
2. An unprivileged sender executes `asset.transfer(sender, controller, amount)` directly against the token contract.
3. The controller’s token balance increases by `amount`, but no account position, pool cash entry, refund reservation, or controller accounting entry is created. [10](#0-9) 
4. Calling a refund-capable path such as `flash_position` with `asset` in `refund_assets` snapshots the already-increased balance and refunds only any additional positive delta. The original `amount` remains behind. [8](#0-7) [11](#0-10) 
5. Attempting to recover it through `borrow(..., to=controller)` or `withdraw(..., to=controller)` reverts with `InvalidFlashloanReceiver`, confirming that the controller recognizes this custody state as unclaimable rather than providing a recovery route. [4](#0-3)

### Citations

**File:** contracts/controller/src/payments.rs (L22-35)
```rust
/// Snapshots `holder`'s balance once per distinct asset address.
pub(crate) fn snapshot_balances(
    env: &Env,
    holder: &Address,
    assets: impl IntoIterator<Item = Address>,
) -> Map<Address, i128> {
    let mut snapshot = Map::new(env);
    for asset in assets {
        if snapshot.contains_key(asset.clone()) {
            continue;
        }
        let balance = token::Client::new(env, &asset).balance(holder);
        snapshot.set(asset, balance);
    }
```

**File:** contracts/controller/src/payments.rs (L39-51)
```rust
/// Refunds only the controller balance increase since `balance_before`,
/// preserving the pre-existing balance; no-op for a nonpositive delta.
pub(crate) fn refund_controller_balance_delta(
    env: &Env,
    asset: &Address,
    balance_before: i128,
    refund_to: &Address,
) {
    let controller = env.current_contract_address();
    let excess = balance_delta_since(env, asset, &controller, balance_before);
    if excess > 0 {
        token::Client::new(env, asset).transfer(&controller, refund_to, &excess);
    }
```

**File:** contracts/controller/src/strategies/flash_position.rs (L120-148)
```rust
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
```

**File:** contracts/controller/src/strategies/flash_position.rs (L217-255)
```rust
fn validate_refund_assets(
    env: &Env,
    cache: &mut Context,
    spoke_id: u32,
    hub_id: u32,
    collaterals: &Vec<(HubAssetKey, i128)>,
    refund_assets: &Vec<Address>,
) {
    let limits = storage::get_position_limits(env);
    assert_with_error!(
        env,
        refund_assets.len() <= limits.max_supply_positions,
        GenericError::InvalidPayments
    );

    let mut seen: Map<Address, bool> = Map::new(env);
    for asset in refund_assets.iter() {
        assert_with_error!(
            env,
            !seen.contains_key(asset.clone()),
            GenericError::InvalidPayments
        );
        seen.set(asset.clone(), true);
        // Refund transfers run after the guard; restrict tokens to listed assets.
        cache.require_listed_active_config(
            spoke_id,
            &HubAssetKey {
                hub_id,
                asset: asset.clone(),
            },
        );
        for (collateral, _) in collaterals.iter() {
            assert_with_error!(
                env,
                asset != collateral.asset,
                GenericError::InvalidPayments
            );
        }
    }
```

**File:** contracts/controller/src/strategies/flash_position.rs (L325-343)
```rust
fn collect_collateral_deposits(
    env: &Env,
    controller: &Address,
    collaterals: &Vec<(HubAssetKey, i128)>,
    before: &Map<Address, i128>,
) -> Vec<(HubAssetKey, i128)> {
    let mut deposits: Vec<(HubAssetKey, i128)> = Vec::new(env);
    for (hub_asset, min_amount) in collaterals.iter() {
        let baseline = before
            .get(hub_asset.asset.clone())
            .unwrap_or_else(|| panic_with_error!(env, GenericError::InternalError));
        let delta = balance_delta_since(env, &hub_asset.asset, controller, baseline);
        assert_with_error!(
            env,
            delta >= min_amount,
            StrategyError::CollateralMinimumNotMet
        );
        if delta > 0 {
            deposits.push_back((hub_asset, delta));
```

**File:** contracts/controller/src/positions/mod.rs (L33-42)
```rust
/// Rejects pool and controller recipients with `InvalidFlashloanReceiver`.
/// Pool self-transfers debit cash without moving tokens; controller receipts
/// would remain unclaimed by balance-delta accounting.
pub(crate) fn require_external_recipient(env: &Env, cache: &mut Context, recipient: &Address) {
    let pool = cache.cached_pool_address();
    assert_with_error!(
        env,
        *recipient != env.current_contract_address() && *recipient != pool,
        FlashLoanError::InvalidFlashloanReceiver
    );
```

**File:** contracts/controller/src/lib.rs (L90-134)
```rust
    /// Supplies `assets` as collateral and returns the account id; `account_id = 0`
    /// creates an account in `spoke_id`. Third parties may only top up existing
    /// supply positions; owners and delegates may add assets.
    #[when_not_paused]
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

**File:** contracts/controller/src/lib.rs (L167-200)
```rust
    /// Flash-loans `amount` of `asset` to a deployed Wasm `receiver`, invoking
    /// its callback with `data`. The pool recovers principal plus fee before return.
    /// Permissionless; requires caller authorization.
    #[when_not_paused]
    fn flash_loan(
        env: Env,
        caller: Address,
        asset: HubAssetKey,
        amount: i128,
        receiver: Address,
        data: Bytes,
    ) {
        strategies::flash_loan::process_flash_loan(&env, &caller, &asset, amount, &receiver, &data);
    }

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
```

**File:** contracts/controller/src/lib.rs (L367-395)
```rust
    /// Accrues pool borrow and supply indexes for `assets`. Permissionless;
    /// requires caller authorization.
    #[when_not_paused]
    fn update_indexes(env: Env, caller: Address, assets: Vec<HubAssetKey>) {
        markets::update_indexes(&env, caller, assets);
    }

    /// Claims pool revenue and forwards measured receipts to the accumulator.
    /// Returns those amounts in asset units, in input order. Permissionless;
    /// requires caller authorization.
    #[when_not_paused]
    fn claim_revenue(env: Env, caller: Address, assets: Vec<HubAssetKey>) -> Vec<i128> {
        markets::claim_revenue(&env, caller, assets)
    }

    /// Refreshes supply LTV snapshots. With `has_risks`, also refreshes gated
    /// liquidation parameters and requires a final health factor of at least
    /// 1.05 WAD. Permissionless; requires caller authorization.
    #[when_not_paused]
    fn update_account_threshold(env: Env, caller: Address, has_risks: bool, account_ids: Vec<u64>) {
        risk::params::update_account_threshold(&env, caller, has_risks, account_ids);
    }

    /// Covers a pool backing shortfall using measured receipts from `payer`.
    /// Refunds excess and returns the amount applied in asset units.
    /// Permissionless; requires payer authorization.
    fn recapitalize(env: Env, payer: Address, hub_asset: HubAssetKey, amount: i128) -> i128 {
        markets::recapitalize(&env, payer, hub_asset, amount)
    }
```
