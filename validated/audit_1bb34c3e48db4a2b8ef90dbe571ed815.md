### Title
Returned flash-position assets can be permanently stranded when omitted from `refund_assets` - (File: contracts/controller/src/strategies/flash_position.rs)

### Summary
`flash_position` mints debt, transfers it to a caller-selected receiver, and then credits only declared collateral deltas and refunds only explicitly listed refund-asset deltas. If the receiver returns the borrowed asset or another listed asset while `refund_assets` omits it, the call can still succeed and leave those tokens at the controller with no accounting or user recovery path. [1](#0-0) 

### Finding Description
`mint_and_forward` borrows `debt.asset`, measures the controller receipt, and transfers the measured amount to `receiver`. [2](#0-1) 

The controller snapshots declared collateral and `refund_assets` balances immediately before invoking `execute_flash_position`, so post-callback settlement is based solely on those finite lists. [3](#0-2) 

After the callback, `collect_collateral_deposits` checks and deposits only assets present in `collaterals`. [4](#0-3) 

`refund_listed_assets` similarly iterates only `refund_assets`; a positive controller balance for any omitted asset is neither supplied nor returned. [5](#0-4) 

A later call cannot recover the stranded balance because `refund_before` is snapshotted before the next callback and refunds only the positive delta above that pre-existing balance. [6](#0-5) 

### Impact Explanation
A user can permanently lose access to borrowed funds returned by the receiver, or to additional callback-delivered assets, while the newly minted debt remains outstanding. The transaction satisfies the protocol’s success conditions once sufficient declared collateral arrives, but the omitted tokens remain controller-held and cannot be claimed by the user or credited to the account. [7](#0-6) 

This is permanent freezing of funds rather than a benign undeclared-input case: the receiver is an accepted part of the `flash_position` flow, and merely omitting the returned asset from `refund_assets` causes its controller balance to be excluded from settlement forever. [5](#0-4) 

### Likelihood Explanation
Any unprivileged caller can reach this path through `flash_position` with its own flash receiver, subject only to a flash-loan-enabled debt market and a healthy final position. [8](#0-7) 

The failure does not require a privileged action, oracle manipulation, or a failed transaction: a receiver can transfer the borrowed token back while the caller supplies collateral separately, and the strategy succeeds if `refund_assets` omitted that token. [9](#0-8) 

### Recommendation
Treat the borrowed asset as an implicit refund asset whenever it is not also a declared collateral asset, and refund its positive post-callback delta to the caller or use it to repay the newly minted debt. [10](#0-9) 

For other assets, enumerate the listed assets eligible in the account’s spoke/hub, snapshot them before the callback, and either refund positive undeclared deltas or reject the call when an undeclared positive delta is detected. At minimum, `debt.asset` should not require an explicit `refund_assets` entry because returning it to the controller is a normal callback outcome. [11](#0-10) 

### Proof of Concept
1. An unprivileged user deploys a flash-position receiver that implements `execute_flash_position`.
2. The user calls `flash_position` with a flash-loan-enabled debt asset, `account_id = 0` or an existing strategy account, one declared collateral market with a positive minimum, and an empty `refund_assets` list. [12](#0-11) 
3. During the callback, the receiver transfers the entire `amount_received` debt asset back to `controller`, then transfers enough of the declared collateral asset to satisfy `min_amount`. [13](#0-12) 
4. The collateral delta is deposited, the new debt remains open, finalization succeeds, and the empty `refund_assets` loop transfers no debt asset back. [7](#0-6) 
5. The returned debt tokens remain on the controller; a second call snapshots that stranded amount as its baseline and refunds only newly received deltas above it. [6](#0-5)

### Citations

**File:** contracts/controller/src/strategies/flash_position.rs (L25-34)
```rust
pub(crate) struct FlashPositionParams<'a> {
    pub account_id: u64,
    pub spoke_id: u32,
    pub mode: PositionMode,
    pub debt: &'a HubAssetKey,
    pub amount: i128,
    pub receiver: &'a Address,
    pub data: &'a Bytes,
    pub collaterals: &'a Vec<(HubAssetKey, i128)>,
    pub refund_assets: &'a Vec<Address>,
```

**File:** contracts/controller/src/strategies/flash_position.rs (L85-91)
```rust
    // Caller-selected receivers require flash loans enabled; multiply uses
    // the configured router and does not require this flag.
    assert_with_error!(
        env,
        cache.cached_pool_sync_data(debt).params.is_flashloanable,
        FlashLoanError::FlashloanNotEnabled
    );
```

**File:** contracts/controller/src/strategies/flash_position.rs (L113-117)
```rust
    let mut extra_assets = vec![env, debt.asset.clone()];
    for (hub_asset, _) in collaterals.iter() {
        extra_assets.push_back(hub_asset.asset.clone());
    }
    prefetch_strategy_prices(&mut cache, &account, &extra_assets);
```

**File:** contracts/controller/src/strategies/flash_position.rs (L119-154)
```rust
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

**File:** contracts/controller/src/strategies/flash_position.rs (L268-294)
```rust
    let controller = env.current_contract_address();
    let before = token::Client::new(env, &debt.asset).balance(&controller);

    let reported = borrow_into_controller(
        env,
        account,
        debt,
        amount,
        false,
        PositionAction::FlashPos,
        cache,
    );

    let measured = balance_delta_since(env, &debt.asset, &controller, before);
    assert_with_error!(env, measured == reported, GenericError::InternalError);
    assert_with_error!(env, measured > 0, GenericError::AmountMustBePositive);

    let forwarded = transfer_amount_measured(
        env,
        &debt.asset,
        &controller,
        receiver,
        measured,
        GenericError::AmountMustBePositive,
    );
    assert_with_error!(env, forwarded > 0, GenericError::AmountMustBePositive);
    forwarded
```

**File:** contracts/controller/src/strategies/flash_position.rs (L325-351)
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
        }
    }
    assert_with_error!(
        env,
        !deposits.is_empty(),
        StrategyError::CollateralMinimumNotMet
    );
    deposits
```

**File:** contracts/controller/src/strategies/flash_position.rs (L372-383)
```rust
fn refund_listed_assets(
    env: &Env,
    caller: &Address,
    refund_assets: &Vec<Address>,
    before: &Map<Address, i128>,
) {
    for asset in refund_assets.iter() {
        let baseline = before
            .get(asset.clone())
            .unwrap_or_else(|| panic_with_error!(env, GenericError::InternalError));
        refund_controller_balance_delta(env, &asset, baseline, caller);
    }
```
