[1](#0-0) ### Title
Stale oracle prices survive the `flash_position` callback and can validate an undercollateralized account - ([File: contracts/controller/src/strategies/flash_position.rs])

### Summary
`flash_position` caches oracle prices before invoking an attacker-controlled receiver, then performs final solvency checks against those stale prices after the callback. A receiver can execute an already-ready governance operation that updates the relevant price-aggregator oracle during the callback, causing the controller to approve debt using pre-update prices and leave the protocol with undercollateralized debt.

### Finding Description
The permissionless `Controller::flash_position` entrypoint accepts a caller-selected Wasm receiver and creates or reuses a Multiply/Long/Short account. [2](#0-1)  The strategy fetches every account, debt, and declared-collateral price before debt forwarding and the external callback. [3](#0-2)  The receiver is then invoked through `execute_flash_position`. [4](#0-3) 

`Context::fetch_prices` only requests assets missing from `token_prices`, while `cached_price` unconditionally returns the stored feed. [5](#0-4) [6](#0-5)  The callback is therefore a time-of-check/time-of-use boundary: governance can call the separate `PriceAggregator::set_oracle` while the controller retains the earlier `PriceFeedRaw`. [7](#0-6) 

Debt is minted to the account and forwarded to the receiver before the callback. [8](#0-7) [9](#0-8)  After the callback, the controller measures and deposits the declared collateral and invokes `strategy_finalize`. [10](#0-9)  That path checks LTV coverage and health factor. [11](#0-10)  The risk calculation calls `load_markets`, which preserves already-cached prices, and then reads `cache.cached_price` for every position. [12](#0-11) 

### Impact Explanation
An attacker can leave an account whose health factor is at least `1.0` under the pre-callback price but below `1.0` under the newly installed oracle. Because the borrowed asset was already forwarded to the receiver, the attacker keeps those proceeds while the account remains undercollateralized. If the stale valuation covers less debt than the minted obligation at liquidation, the shortfall becomes protocol bad debt and is ultimately borne by suppliers.

### Likelihood Explanation
The required path is unprivileged: the attacker owns the account, controls the flash receiver, and supplies the callback data. The exploit requires a governance operation that is already executable and changes an oracle enough to make the pre- and post-update valuations differ. That precondition limits the attack window, but oracle replacements and sanity/configuration updates are normal governance operations, so this is a Medium-severity race rather than a purely hypothetical issue.

### Recommendation
Refresh oracle prices after the receiver callback and before `strategy_finalize`, or invalidate `Context::token_prices` at the end of the callback window so `calculate_account_risk_totals` resolves post-callback values. Preserve pool-returned market indexes where needed, but do not reuse pre-callback `PriceFeedRaw` values for final solvency. A focused regression test should update an aggregator oracle inside `execute_flash_position` and assert that the final health check observes the new price.

### Proof of Concept
1. Wait until governance has a ready operation that changes collateral token `C`'s oracle from a higher resolved price `P_old` to a lower resolved price `P_new`, or changes debt token `D`'s oracle to a higher price.
2. Call `Controller::flash_position` with `account_id = 0`, an attacker-controlled `receiver`, a flashloanable `debt = D`, `amount = X`, and `collaterals = [(C, min_c)]`.
3. The controller caches `C` and `D` at `P_old`, mints `X` units of `D`, forwards them to the receiver, and invokes `execute_flash_position`.
4. Inside the callback, the receiver executes the ready governance operation and then transfers `min_c` units of `C` to the controller.
5. The controller measures the `C` receipt, deposits it, and finalizes the account using the cached `P_old`.
6. Choose `X` and `min_c` such that `min_c × P_old × liquidation_threshold ≥ X × debt_price_old`, but `min_c × P_new × liquidation_threshold < X × debt_price_new`; the call succeeds while the persisted account is immediately undercollateralized under current oracle state.

### Citations

**File:** contracts/controller/src/strategies/flash_position.rs (L113-143)
```rust
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
```

**File:** contracts/controller/src/strategies/flash_position.rs (L145-154)
```rust
    let deposits = collect_collateral_deposits(env, &controller, collaterals, &collateral_before);
    process_deposit(env, &controller, &mut account, &deposits, &mut cache);

    refund_listed_assets(env, caller, refund_assets, &refund_before);

    // Check before and after finalization: its LTV refresh can prune zero-scaled
    // supply, and persistence removes empty accounts.
    require_flash_position_still_open(env, &account, debt);
    strategy_finalize(env, account_id, &mut account, &mut cache);
    require_flash_position_still_open(env, &account, debt);
```

**File:** contracts/controller/src/strategies/flash_position.rs (L271-279)
```rust
    let reported = borrow_into_controller(
        env,
        account,
        debt,
        amount,
        false,
        PositionAction::FlashPos,
        cache,
    );
```

**File:** contracts/controller/src/strategies/flash_position.rs (L285-293)
```rust
    let forwarded = transfer_amount_measured(
        env,
        &debt.asset,
        &controller,
        receiver,
        measured,
        GenericError::AmountMustBePositive,
    );
    assert_with_error!(env, forwarded > 0, GenericError::AmountMustBePositive);
```

**File:** contracts/controller/src/lib.rs (L189-200)
```rust
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

**File:** contracts/controller/src/context.rs (L141-149)
```rust
    /// Fetches missing prices in one aggregator call; retains cached prices.
    pub(crate) fn fetch_prices(&mut self, assets: &Vec<Address>) {
        let missing = collect_uncached_keys(&self.env, assets, &self.token_prices);
        if missing.is_empty() {
            return;
        }
        let fetched = external::price_aggregator::fetch_prices(&self.env, &missing);
        for (asset, feed) in fetched.iter() {
            self.token_prices.set(asset, feed);
```

**File:** contracts/controller/src/context.rs (L153-159)
```rust
    /// Returns a previously loaded price; fails if the cache has no entry.
    pub(crate) fn cached_price(&mut self, asset: &Address) -> PriceFeed {
        let raw = self
            .token_prices
            .get(asset.clone())
            .unwrap_or_else(|| panic_with_error!(&self.env, OracleError::OracleNotConfigured));
        (&raw).into()
```

**File:** contracts/price-aggregator/src/lib.rs (L110-113)
```rust
    #[only_owner]
    fn set_oracle(env: Env, key: PriceKey, oracle: AssetOracle) {
        renew_instance(&env);
        admin::set_oracle(&env, key, oracle);
```

**File:** contracts/controller/src/positions/mod.rs (L83-90)
```rust
pub(crate) fn enforce_post_pool_solvency(
    env: &Env,
    cache: &mut Context,
    account: &mut Account,
) -> bool {
    let restamped = risk::restamp_listed_supply_ltv(cache, account);
    validation::require_post_pool_risk_gates(env, cache, account);
    restamped
```

**File:** contracts/controller/src/risk/totals.rs (L163-175)
```rust
    cache.load_markets(&portfolio_hub_keys(
        supply_positions.keys(),
        &borrow_positions.keys(),
    ));

    let mut total_collateral = Wad::ZERO;
    let mut ltv_collateral = Wad::ZERO;
    let mut weighted_collateral = Wad::ZERO;
    for (hub_asset, position) in iter_typed_positions(supply_positions) {
        let feed = cache.cached_price(&hub_asset.asset);
        let market_index = cache.cached_market_index(&hub_asset);

        let value = position_value(
```
