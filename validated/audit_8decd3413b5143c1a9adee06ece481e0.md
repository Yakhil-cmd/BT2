### Title
Stale pre-callback oracle configuration permits undercollateralized flash-position debt - (File: contracts/controller/src/strategies/flash_position.rs)

### Summary
`flash_position` prefetches and freezes oracle prices before invoking the untrusted receiver, then performs collateral crediting and all final risk checks against that stale `Context`. A receiver can execute a ready, permissionless governance `ConfigureAssetOracle` operation during the callback, replacing the collateral oracle before finalization while the controller continues to value the account with the pre-callback price. This creates a solvency-check bypass and can leave the pool with immediately undercollateralized or insolvent debt.

### Finding Description
The flow in `process_flash_position` constructs one `Context`, loads the debt and collateral prices before the callback, mints and forwards debt, invokes `receiver.execute_flash_position`, and only afterward deposits the callback collateral and calls `strategy_finalize`. [1](#0-0) 

`Context::fetch_prices` deliberately fetches only missing assets and retains any already cached `PriceFeedRaw`; later `cached_price` returns that retained value rather than querying the aggregator again. [2](#0-1) 

The receiver callback is an arbitrary Wasm contract invoked through `env.invoke_contract`, and it is not constrained to token transfers or swaps. [3](#0-2) 

Governance `execute` accepts `executor = None`; in that case no executor authorization or role is required, so an unprivileged receiver can trigger any operation that is already ready and unexpired. [4](#0-3) 

A ready `AdminOperation::ConfigureAssetOracle` resolves to the price aggregator's `set_oracle` entrypoint. [5](#0-4) 

`set_oracle` validates, probes, stores, and emits the replacement oracle configuration, so subsequent ordinary reads use the new source while the in-flight controller `Context` continues using the old feed. [6](#0-5) 

After the callback returns, `collect_collateral_deposits` credits measured token deltas, `strategy_finalize` calls `enforce_post_pool_solvency`, and that function evaluates the account with the same stale context rather than reprieving the changed oracle. [7](#0-6) [8](#0-7) 

### Impact Explanation
An attacker can atomically open a leveraged account whose debt is only collateralized under the pre-callback oracle. The callback executes a ready oracle replacement that materially lowers the collateral's accepted price before `strategy_finalize`, but the final LTV and health-factor checks still consume the stale higher `PriceFeedRaw`. The attacker can leave part of the flash-minted debt as profit while the protocol retains an account that is undercollateralized under the live oracle.

This is theft of pool assets and can become protocol insolvency if the residual collateral cannot cover the minted debt. The receiver does not need a privileged controller, pool, governance, or oracle role; it only needs the borrowed funds and a governance operation already in the `Ready` state. The operation itself was legitimately scheduled, but the controller incorrectly spans its execution inside an untrusted callback while retaining a pre-operation valuation snapshot.

### Likelihood Explanation
The attack requires:

1. A `ConfigureAssetOracle` governance operation for the chosen collateral market to be ready and unexpired.
2. A flash-loanable debt market and enough liquidity for the desired borrow.
3. A receiver contract that can return the required collateral amount while executing `Governance::execute(..., executor=None, target=price_aggregator, function="set_oracle", ...)` inside `execute_flash_position`.
4. The post-operation collateral price to be low enough that the position would fail the risk gate if refreshed.

The path is fully reachable by an unprivileged caller: `flash_position` accepts caller-chosen Wasm receivers, and anonymous execution of ready governance operations is explicitly supported. The only external dependency is the existence of a ready oracle-change operation, which is a normal governance lifecycle state.

### Recommendation
Do not allow governance, oracle, router, or other state-changing external calls between price prefetch and final risk validation without refreshing affected cached state. Concretely:

- Re-fetch and validate all debt/collateral prices after `invoke_receiver`, before collateral deposit and `strategy_finalize`, rather than relying on pre-callback `Context` entries.
- Alternatively, snapshot an aggregator configuration/version key before the callback and require it to be unchanged after the callback; revert on change.
- Consider blocking governance execution during controller callbacks through an aggregator/governance nonce or an explicit protocol-wide reentrancy boundary, if supported by the deployment topology.
- Add a regression test where a mock flash-position receiver executes a ready oracle replacement mid-callback and assert that `flash_position` reverts rather than finalizing with stale prices.

### Proof of Concept
1. Governance schedules `AdminOperation::ConfigureAssetOracle` replacing collateral token `C`'s oracle with a lower-priced valid configuration and waits until the operation is `Ready`.
2. Attacker calls `Controller::flash_position` with:
   - `account_id = 0`
   - `mode = PositionMode::Multiply`
   - `debt = D`, a flash-loanable market
   - `receiver = A`, an attacker-controlled Wasm contract
   - `collaterals = [(C, minimum_C)]`
   - `data` containing the ready operation's `target=function=args`, predecessor, and salt.
3. `process_flash_position` caches the current high price for `C` and debt `D` at `prefetch_strategy_prices`, mints `D`, forwards it to `A`, and calls `A.execute_flash_position`.
4. Inside the callback, `A` calls `Governance::execute(None, price_aggregator, "set_oracle", ..., predecessor, salt)`. The ready operation succeeds because no executor is required, and `price_aggregator.set_oracle` stores the lower-priced oracle.
5. `A` returns enough `C` to satisfy `minimum_C`, measured as a controller balance delta.
6. The controller deposits `C` and calls `strategy_finalize`, but `Context::cached_price(C)` still returns the stale high pre-callback feed, so the LTV and HF gates pass.
7. After commit, a fresh controller read uses the replacement oracle, values `C` lower, and reports the new account as unhealthy/liquidatable while the attacker retains the unspent portion of the flash-minted debt or proceeds obtained from it.

### Citations

**File:** contracts/controller/src/strategies/flash_position.rs (L78-154)
```rust
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
    );

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
    require_flash_position_still_open(env, &account, debt);
```

**File:** contracts/controller/src/strategies/flash_position.rs (L297-322)
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
```

**File:** contracts/controller/src/strategies/flash_position.rs (L325-352)
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
}
```

**File:** contracts/controller/src/context.rs (L141-160)
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
    }
```

**File:** contracts/governance/src/timelock/lifecycle.rs (L81-110)
```rust
/// Executes a scheduled operation against `target` once its delay has elapsed and
/// it has not expired, and returns the invocation's result. Rejects operations
/// that target this contract itself (use `execute_self` for those). Clears the
/// operation's scheduled state on completion.
pub(crate) fn execute(
    env: &Env,
    executor: Option<Address>,
    target: Address,
    function: Symbol,
    args: Vec<Val>,
    predecessor: BytesN<32>,
    salt: BytesN<32>,
) -> Val {
    assert_with_error!(
        env,
        target != env.current_contract_address(),
        GenericError::InternalError
    );
    let operation = Operation {
        target,
        function,
        args,
        predecessor,
        salt,
    };
    let operation_id = prepare_execute(env, executor.as_ref(), &operation);
    let result = execute_operation(env, &operation);
    finish_execute(env, &operation_id);
    result
}
```

**File:** contracts/governance/src/op.rs (L389-405)
```rust
        AdminOperation::ConfigureAssetOracle(args) => {
            let oracle = resolve_oracle(env, &args.key, &args.oracle);
            price_aggregator_operation(
                env,
                "set_oracle",
                vec![env, args.key.clone().into_val(env), oracle.into_val(env)],
            )
        }
        AdminOperation::EditOracleTolerance(args) => {
            let tolerance =
                validate::tolerance::validate_and_calculate_tolerances(env, args.tolerance);
            price_aggregator_operation(
                env,
                "set_tolerance",
                vec![env, args.key.clone().into_val(env), tolerance.into_val(env)],
            )
        }
```

**File:** contracts/price-aggregator/src/admin.rs (L69-96)
```rust
/// Validates `oracle` and attests its sources, then probes it: a hard probe
/// for Aquarius LP oracles that panics on any unusable outcome, or a soft
/// probe otherwise that panics only on configuration-level failures. Stores
/// the oracle, revalidates dependents, and emits the registry event.
///
/// A replacement must keep the stored `asset_decimals`. Panics with
/// `OracleError::InvalidOracleDecimals` otherwise.
pub(crate) fn set_oracle(env: &Env, key: PriceKey, oracle: AssetOracle) {
    if let Some(stored) = registry::get_oracle(env, &key) {
        assert_with_error!(
            env,
            stored.asset_decimals == oracle.asset_decimals,
            OracleError::InvalidOracleDecimals
        );
    }
    validate_asset_oracle(env, &key, &oracle);
    attest_sources(env, &key, &oracle);
    let mut session = Session::new(env);
    if oracle.has_aquarius_lp_source() {
        engine::probe_priceable(&mut session, &key, &oracle);
    } else {
        engine::probe(&mut session, &key, &oracle);
    }

    registry::store_oracle(env, &key, &oracle);
    revalidate_dependents(env, &key);
    registry::emit(env, &key, &oracle);
}
```

**File:** contracts/controller/src/positions/mod.rs (L83-91)
```rust
pub(crate) fn enforce_post_pool_solvency(
    env: &Env,
    cache: &mut Context,
    account: &mut Account,
) -> bool {
    let restamped = risk::restamp_listed_supply_ltv(cache, account);
    validation::require_post_pool_risk_gates(env, cache, account);
    restamped
}
```
