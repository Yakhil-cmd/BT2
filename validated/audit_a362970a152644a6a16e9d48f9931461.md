### Title
Flash-position solvency can be proven against a revoked oracle price cached before the callback - (File: contracts/controller/src/strategies/flash_position.rs)

### Summary
`flash_position` prefetches oracle prices before invoking the attacker-selected receiver, while `Context` intentionally retains every fetched price for the remainder of the controller call. [1](#0-0) [2](#0-1)  A receiver can execute a ready governance `ConfigureAssetOracle` operation against the separate price-aggregator contract during that callback, after which the post-callback collateral accounting and solvency check still use the superseded cached price. [3](#0-2) [4](#0-3)  This can leave an account undercollateralized immediately after the oracle change, allowing pool funds to be extracted through debt that the active price no longer supports. [5](#0-4) 

### Finding Description
The strategy builds `extra_assets` from the debt token and declared collateral tokens, then calls `prefetch_strategy_prices` before the receiver callback. [1](#0-0)  `Context::fetch_prices` skips any asset already present in `token_prices`, and `cached_price` later returns that retained value rather than re-reading the aggregator. [2](#0-1)  Governance permits anyone to execute a ready, non-expired scheduled operation, including oracle-configuration operations proposed by the owner. [6](#0-5)  Because the callback invokes the receiver through `invoke_contract`, the receiver can call the separate governance contract and have it execute a ready `ConfigureAssetOracle` operation against the price aggregator while the controller call remains in progress. [7](#0-6) [3](#0-2) 

After callback return, the controller measures the declared collateral balances, deposits them, and calls `strategy_finalize` without invalidating the price cache. [8](#0-7)  The final account risk calculation therefore multiplies collateral and debt by `cache.cached_price`, not by the currently configured oracle result. [9](#0-8)  The stale numerator and denominator are then used to derive the health factor that decides whether the newly minted debt may persist. [10](#0-9) 

### Impact Explanation
An attacker can atomically borrow against collateral at the last price admitted by an oracle configuration that governance replaces in the same transaction. [11](#0-10)  When the new oracle reports a sufficiently lower collateral value, the account can pass the old-price LTV and health-factor checks but be insolvent or liquidatable under the active configuration. [12](#0-11)  Unspent debt tokens declared in `refund_assets` are returned to the caller while the minted debt remains, so the attacker can retain part of the borrowed value and leave the pool with bad debt. [8](#0-7) [13](#0-12)  This is protocol insolvency resulting from an unprivileged `flash_position` caller plus permissionless execution of an already-ready governance operation. [3](#0-2) 

### Likelihood Explanation
The attack is conditional on a material oracle-changing operation already being scheduled and executable, but execution requires no executor identity when `executor=None`. [3](#0-2)  `flash_position` accepts any deployed Wasm receiver other than the controller or pool and lets the initiator choose both that receiver and its callback data. [14](#0-13)  The attack therefore requires only an attacker-controlled receiver and enough temporary inventory or routing to deliver the declared collateral minimum; it does not require a privileged key. [15](#0-14)  Its exploitability is bounded by the size and timing of the oracle transition rather than by authorization complexity. [2](#0-1) 

### Recommendation
Invalidate and re-fetch all risk-bearing cached oracle data after the receiver callback and before collateral deposit, refund handling, and `strategy_finalize`. [8](#0-7)  If any required price becomes unavailable or the refreshed risk check fails, the entire transaction should revert, which also atomically rolls back the receiver’s governance execution. [16](#0-15)  An alternative is an oracle version or configuration epoch captured before the callback and compared before finalization, with any change aborting the position flow. [2](#0-1) 

### Proof of Concept
```text
Precondition:
  collateral C: cached oracle price = 100 USD, LTV = 80%
  ready governance op: ConfigureAssetOracle(C) -> source reporting 70 USD
  debt D: USDC, flashloanable

Attacker calls:
  controller.flash_position(
      caller      = attacker,
      account_id  = 0,
      spoke_id    = S,
      mode        = Multiply,
      debt        = (hub, USDC),
      amount      = 80 USDC,
      receiver    = attacker_wasm,
      data        = ready ConfigureAssetOracle payload,
      collaterals = [((hub, C), 1 C)],
      refund_assets = [USDC],
  )
```

Inside `execute_flash_position`, the receiver buys or supplies 1 `C`, calls `Governance::execute(None, price_aggregator, "set_oracle", configure_args, predecessor, salt)`, and transfers the `C` receipt to the controller. [17](#0-16) [18](#0-17)  The controller’s prefetched price remains 100 USD because `fetch_prices` only loads missing entries and `cached_price` reads the existing map entry. [2](#0-1)  The final stale valuation records `1 C × 100 × 80% = 80 USD` of LTV collateral against `80 USDC` of debt, while the active 70-USD oracle values the collateral at only 56 USD of borrowing capacity. [19](#0-18)  The attacker keeps the resulting 24-USD immediate insolvency spread, before interest and liquidation effects. [13](#0-12)

### Citations

**File:** contracts/controller/src/strategies/flash_position.rs (L69-90)
```rust
    require_wasm_receiver(env, receiver);

    let controller = env.current_contract_address();
    assert_with_error!(
        env,
        *receiver != controller,
        FlashLoanError::InvalidFlashloanReceiver
    );

    let mut cache = Context::new(env);
    let pool_addr = cache.cached_pool_address();
    assert_with_error!(
        env,
        *receiver != pool_addr,
        FlashLoanError::InvalidFlashloanReceiver
    );
    // Caller-selected receivers require flash loans enabled; multiply uses
    // the configured router and does not require this flag.
    assert_with_error!(
        env,
        cache.cached_pool_sync_data(debt).params.is_flashloanable,
        FlashLoanError::FlashloanNotEnabled
```

**File:** contracts/controller/src/strategies/flash_position.rs (L93-153)
```rust
    let (account_id, mut account) = account::load_or_create_account(
        env,
        caller,
        account_id,
        spoke_id,
        mode,
        account::AccountGuard::Multiply,
        &mut cache,
    );

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
```

**File:** contracts/controller/src/strategies/flash_position.rs (L297-323)
```rust
fn invoke_receiver(
    env: &Env,
    receiver: &Address,
    initiator: &Address,
    account_id: u64,
    asset: &Address,
    amount: i128,
    amount_received: i128,
    controller: &Address,
    data: &Bytes,
) {
    env.invoke_contract::<()>(
        receiver,
        &Symbol::new(env, "execute_flash_position"),
        (
            initiator.clone(),
            account_id,
            asset.clone(),
            amount,
            0i128,
            amount_received,
            controller.clone(),
            data.clone(),
        )
            .into_val(env),
    );
}
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

**File:** contracts/controller/src/context.rs (L141-159)
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
        }
    }

    /// Returns a previously loaded price; fails if the cache has no entry.
    pub(crate) fn cached_price(&mut self, asset: &Address) -> PriceFeed {
        let raw = self
            .token_prices
            .get(asset.clone())
            .unwrap_or_else(|| panic_with_error!(&self.env, OracleError::OracleNotConfigured));
        (&raw).into()
```

**File:** docs/reference/endpoints.md (L199-215)
```markdown
`execute` must match a scheduled operation hash and predecessor and run within its execution window. With `executor = None`, anyone can execute a ready operation. With `Some(address)`, that address must authorize and hold EXECUTOR_ROLE.

| Endpoint | Authority / effect |
| --- | --- |
| `deploy_controller(wasm_hash: BytesN<32>) -> Address` | Owner; one-time deployment |
| `controller() -> Address` | Open view / resolver |
| `deploy_price_aggregator(wasm_hash: BytesN<32>) -> Address` | Owner; one-time deployment |
| `price_aggregator() -> Address` | Open view / resolver |
| `execute(executor: Option<Address>, target: Address, function: Symbol, args: Vec<Val>, predecessor: BytesN<32>, salt: BytesN<32>) -> Val` | Ready scheduled operation; optional executor |
| `cancel(canceller: Address, operation_id: BytesN<32>)` | CANCELLER_ROLE; recovery ops cannot be cancelled; target cannot cancel own revocation |
| `get_min_delay() -> u32` | Open view / resolver |
| `get_operation_state(operation_id: BytesN<32>) -> OperationState` | Open view / resolver |
| `get_operation_ledger(operation_id: BytesN<32>) -> u32` | Open view / resolver |
| `hash_operation(target: Address, function: Symbol, args: Vec<Val>, predecessor: BytesN<32>, salt: BytesN<32>) -> BytesN<32>` | Open view / resolver |
| `resolve_oracle_tolerance(tolerance: u32) -> OracleTolerance` | Open view / resolver |
| `resolve_asset_oracle(key: PriceKey, oracle: AssetOracle) -> AssetOracle` | Open view / resolver |
| `propose(proposer: Address, op: AdminOperation, salt: BytesN<32>) -> BytesN<32>` | PROPOSER_ROLE; the proposer must also be the current owner for ownership transfers, code upgrades (`UpgradeGov`, `UpgradeController`, `UpgradePool`, `UpgradePositionNft`, `UpgradePriceAggregator`, `MigrateController`), the timelock minimum delay (`UpdateGovDelay`), price and swap sources (`SetPriceAggregator`, `ConfigureAssetOracle`, `EditOracleTolerance`, `SetSwapAggregator`), `ApproveBlendPool`, `SetAccumulator` and `GrantGovRole`; `RevokeGovRole` cannot target the proposer or the owner |
```

**File:** contracts/controller/src/risk/totals.rs (L163-207)
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
            env,
            position.scaled_amount,
            market_index.supply_index,
            feed.price,
        );
        let gate_value = position_value_floor(
            env,
            position.scaled_amount,
            market_index.supply_index,
            feed.price,
        );

        total_collateral = total_collateral.checked_add(env, value);
        // A gated threshold can stay below refreshed LTV; clamp the borrow limit to it.
        let effective_ltv = position.loan_to_value.min(position.liquidation_threshold);
        ltv_collateral =
            ltv_collateral.checked_add(env, effective_ltv.apply_to_wad_floor(env, gate_value));
        weighted_collateral = weighted_collateral.checked_add(
            env,
            position
                .liquidation_threshold
                .apply_to_wad_floor(env, gate_value),
        );
    }

    let total_debt = sum_debt_usd_loaded(env, cache, borrow_positions, position_value_ceil);

    let health_factor = if total_debt == Wad::ZERO {
        Wad::from(i128::MAX)
    } else {
        weighted_collateral.div_floor_saturating(env, total_debt)
    };
```
