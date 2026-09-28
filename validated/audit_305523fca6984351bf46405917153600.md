### Title
Stale oracle snapshot allows undercollateralized `flash_position` after permissionless governance execution - (File: contracts/controller/src/strategies/flash_position.rs)

### Summary

`flash_position` prefetches debt and collateral prices into an invocation-local `Context`, invokes an arbitrary receiver, and then performs final solvency checks using the same cached prices. A receiver can execute any already-ready governance operation while inside the callback, including an operation that changes the price-aggregator configuration for the collateral asset. Because governance execution with `executor = None` is permissionless and the aggregator is no longer on the call stack after prefetching, the callback can change the oracle after the old price has been cached. The final risk check then approves the new debt using a stale collateral price. [1](#0-0) [2](#0-1) [3](#0-2) 

### Finding Description

`process_flash_position` adds the debt asset and every declared collateral asset to `extra_assets` and calls `prefetch_strategy_prices` before `mint_and_forward` and `invoke_receiver`. [4](#0-3) 

`Context::fetch_prices` stores each fetched `PriceFeedRaw`, while `cached_price` later returns that retained value rather than querying the aggregator again. [2](#0-1) 

The receiver callback is arbitrary contract code and runs before collateral deposit processing, refunds, and `strategy_finalize`; finalization receives the same mutable `Context` containing the pre-callback prices. [5](#0-4) 

Governance `execute` accepts `executor = None`, which skips both executor authentication and the executor-role check, then invokes the scheduled target and clears the operation. [3](#0-2) [6](#0-5) 

Governance can schedule operations targeting the configured price aggregator, and the aggregator exposes owner-only `set_oracle`; governance is the aggregator owner in the deployed authority chain. [7](#0-6) [8](#0-7) [9](#0-8) 

This creates a cross-contract check-time/use-time mismatch: the controller checks the collateral value under the oracle snapshot fetched before the callback, while the committed post-transaction state is priced under the oracle installed during the callback.

### Impact Explanation

An attacker can create a leveraged account that is solvent only under the stale collateral price.

For example:

- Collateral oracle price before the operation: `$100`
- Collateral oracle price after a ready `set_oracle` operation: `$50`
- Collateral LTV: `60%`
- Borrowed debt value: `$100`

The stale check requires approximately `$166.67` of collateral at `$100`, or `1.6667` units. At the new `$50` price, those units cost only `$83.33`. The receiver can buy and deposit them, retain approximately `$16.67` of the borrowed funds, and leave a position with `$100` debt backed by `$83.33` of collateral.

That produces immediate bad debt and lets the attacker extract protocol-backed borrowed assets. At sufficient size, repeated positions cause protocol insolvency and loss of supplier funds.

### Likelihood Explanation

The attacker cannot select the oracle configuration. Exploitation requires an already-approved governance operation that is ready to execute and changes a relevant price feed or transitive price dependency.

Once such an operation is ready, no privileged role is needed to execute it: the receiver calls `execute` with `executor = None`. The operation is not cancelled or blocked by the flash guard because the callback is not reentering the controller; it is calling governance and then the aggregator, neither of which remains on the controller call stack after prefetching.

The attack is therefore conditional rather than always available, but it requires no leaked key, governance compromise, malicious oracle report, or protocol parameter mistake beyond a legitimate scheduled oracle change.

### Recommendation

Do not use pre-callback prices for post-callback solvency decisions.

A robust fix would make valuation state invalidation explicit:

1. Record an aggregator configuration/version epoch before external receiver or router execution.
2. Increment that epoch on every aggregator configuration mutation that can affect resolved prices.
3. Recheck it after the callback and refresh the controller `Context` if it changed.
4. Apply the same protection to every guarded external execution window that later performs risk checks, including `flash_position`, `multiply`, `swap_debt`, `swap_collateral`, `repay_debt_with_collateral`, and Blend migration.
5. Alternatively, clear/refetch all cached price and market inputs after the callback and run final risk checks against a fresh pricing context.

The mitigation must cover transitive oracle changes, not only a `set_oracle` call whose `PriceKey` is one of the direct collateral tokens.

### Proof of Concept

1. Governance schedules and a timelock makes ready an operation that resolves to:

   ```text
   target      = price_aggregator
   function    = "set_oracle"
   args        = (PriceKey::Token(COLLATERAL), new_oracle)
   predecessor = zero bytes
   salt        = scheduled salt
   ```

   The new configuration is valid and resolves collateral at `$50`, replacing a configuration that resolves it at `$100`.

2. The attacker deploys a receiver and calls:

   ```text
   controller.flash_position(
       caller        = attacker,
       account_id    = 0,
       spoke_id      = S,
       mode          = Multiply,
       debt          = HubAssetKey { hub_id: H, asset: DEBT_TOKEN },
       amount        = debt amount worth $100,
       receiver      = attacker_receiver,
       data          = encoded ready-operation fields,
       collaterals   = [(HubAssetKey { hub_id: H, asset: COLLATERAL }, 1.6667 units)],
       refund_assets = [DEBT_TOKEN]
   )
   ```

3. The controller prefetches `$100` for `COLLATERAL`, mints the debt position, forwards the borrowed tokens to `attacker_receiver`, and invokes `execute_flash_position`. [10](#0-9) 

4. Inside the receiver callback:

   ```rust
   governance.execute(
       &None,
       &aggregator,
       &Symbol::new(&env, "set_oracle"),
       &operation_args,
       &zero_predecessor,
       &salt,
   );

   // Buy 1.6667 collateral units at the new $50 price.
   collateral_token.transfer(&receiver, &controller, &1_6667);
   ```

   The governance call is authorized as a permissionless ready-operation execution, and the subsequent `set_oracle` invocation succeeds because governance owns the aggregator. [11](#0-10) [8](#0-7) 

5. After the callback returns, the controller measures and deposits the collateral, but `strategy_finalize` uses the `Context` that still contains collateral at `$100`. The position therefore passes the health-factor and LTV checks despite being worth only `$83.33` under the committed oracle. [12](#0-11) [2](#0-1) 

6. The attacker keeps the remaining borrowed tokens. The account is immediately undercollateralized and later liquidation cannot recover the full debt.

### Citations

**File:** contracts/controller/src/strategies/flash_position.rs (L113-154)
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

    let deposits = collect_collateral_deposits(env, &controller, collaterals, &collateral_before);
    process_deposit(env, &controller, &mut account, &deposits, &mut cache);

    refund_listed_assets(env, caller, refund_assets, &refund_before);

    // Check before and after finalization: its LTV refresh can prune zero-scaled
    // supply, and persistence removes empty accounts.
    require_flash_position_still_open(env, &account, debt);
    strategy_finalize(env, account_id, &mut account, &mut cache);
    require_flash_position_still_open(env, &account, debt);
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

**File:** contracts/governance/src/timelock/lifecycle.rs (L99-108)
```rust
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
```

**File:** contracts/governance/src/op.rs (L80-88)
```rust
/// Builds a `ResolvedOperation` targeting the price aggregator contract with
/// the `Standard` delay tier.
fn price_aggregator_operation(env: &Env, function: &str, args: Vec<Val>) -> ResolvedOperation {
    ResolvedOperation {
        target: storage::get_price_aggregator(env),
        function: Symbol::new(env, function),
        args,
        delay_tier: DelayTier::Standard,
    }
```

**File:** contracts/price-aggregator/src/lib.rs (L108-114)
```rust
    /// Owner-only. Registers or replaces the oracle configuration for `key`. A
    /// replacement must keep the stored `asset_decimals`.
    #[only_owner]
    fn set_oracle(env: Env, key: PriceKey, oracle: AssetOracle) {
        renew_instance(&env);
        admin::set_oracle(&env, key, oracle);
    }
```

**File:** contracts/price-aggregator/README.md (L69-74)
```markdown
## Owner

Governance deploys the contract and passes itself as the constructor's
`owner`. `#[only_owner]` gates every write, `upgrade` included. The ABI has no
ownership transfer, accept, or renounce entrypoint. The controller reads
`prices` for risk checks and `quotes` for views.
```
