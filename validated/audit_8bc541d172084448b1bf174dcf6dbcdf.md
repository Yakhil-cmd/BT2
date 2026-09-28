### Title
Stale prefetched oracle prices survive a `flash_position` callback’s governance execution - (File: contracts/controller/src/context.rs)

### Summary
`flash_position` loads all prices into the invocation-local `Context` before invoking the attacker-controlled receiver. That cache is never invalidated after the callback, even though the receiver can permissionlessly execute a ready governance operation against the price aggregator. The final solvency check therefore values the newly minted debt and newly deposited collateral with a retired oracle configuration, allowing an account to pass with collateral that is insufficient under the now-current oracle configuration.

### Finding Description
`process_flash_position` prefetches the debt and collateral prices before entering the callback. [1](#0-0)  `Context::fetch_prices` stores fetched feeds in `token_prices`, and `cached_price` later returns the stored value without rereading the aggregator. [2](#0-1) 

During the callback, the receiver can call `Governance::execute` for a ready operation; with `executor: None`, the endpoint performs no executor authorization check. [3](#0-2)  A ready `ConfigureAssetOracle` or equivalent aggregator-targeted operation can replace the oracle configuration used for either the debt or collateral asset. [4](#0-3) 

After the callback returns, the controller measures and deposits the declared collateral, then calls `strategy_finalize`. [5](#0-4)  `strategy_finalize` runs the post-pool solvency gate using the same `Context`. [6](#0-5)  The risk calculation reads `cache.cached_price(&hub_asset.asset)` and computes health factor from those stale prices. [7](#0-6) 

This is the lending analog of use-after-free: the flow retains a pointer-like cached object to an oracle state that was retired during the callback, then continues using it for authorization-critical risk arithmetic. The flash guard prevents direct monetary reentry into the controller, but it does not prevent the receiver from calling the independent governance and price-aggregator contracts. [8](#0-7) 

### Impact Explanation
An attacker can borrow at an obsolete debt price or collateralize at an obsolete collateral price. After the transaction commits, the current oracle configuration values the account below the solvency threshold while the borrowed assets are already held by the attacker’s receiver. The minted debt is backed by insufficient collateral, causing a liquidation shortfall or protocol bad debt; the ultimate loss is borne by pool suppliers. This is theft of user funds and protocol insolvency, not merely a stale view or accounting display.

### Likelihood Explanation
The attack requires a ready governance operation that materially changes the valuation of either the flash-borrowed debt asset or the supplied collateral asset. Such operations are public, deterministic, and permissionlessly executable once ready, so an attacker can monitor the timelock and submit `flash_position` in the same ledger in which the operation becomes executable. The attacker controls both `caller` and `receiver`, and `account_id = 0` creates the required account. The only external precondition is existence of a suitable ready oracle operation; no privileged role, leaked key, malicious oracle, or controller reentry is needed.

### Recommendation
After `with_flash_guard` returns, invalidate `Context::token_prices` and refetch every price used by collateral deposit, risk-parameter stamping, and the final solvency gate. More generally, clear every cache entry that an external callback can indirectly mutate; prices are the reachable example here because governance can update the price aggregator during the callback. Add a regression test where `execute_flash_position` executes a ready oracle operation before returning collateral, and assert that finalization uses the post-operation price.

### Proof of Concept
1. Governance schedules `ConfigureAssetOracle` for debt asset `D`; the operation is now `Ready` and changes `D`’s configured valuation upward, or schedules an equivalent change that lowers collateral asset `C`’s valuation.
2. The attacker contract calls:

```rust
flash_position(
    caller = attacker_contract,
    account_id = 0,
    spoke_id = listed_spoke,
    mode = PositionMode::Multiply,
    debt = D_key,
    amount = borrow_amount,
    receiver = attacker_contract,
    data = encoded_ready_operation,
    collaterals = [(C_key, min_collateral)],
    refund_assets = [],
)
```

3. The controller prefetches `D` and `C` using the pre-operation oracle configuration. [9](#0-8) 
4. Inside `with_flash_guard`, the controller mints `borrow_amount` of `D` onto the new account and forwards the measured tokens to `receiver`. [10](#0-9) 
5. In `execute_flash_position`, the receiver first transfers `min_collateral` of `C` to the controller, then calls:

```rust
governance.execute(
    None,
    price_aggregator,
    scheduled_function,
    scheduled_args,
    scheduled_predecessor,
    scheduled_salt,
)
```

6. The callback returns. The controller measures the collateral receipt and calls `strategy_finalize`; `cached_price` still returns the pre-operation feeds because `fetch_prices` refuses to reload cached assets. [2](#0-1) 
7. The account passes the stale-price solvency check and persists. A subsequent view or liquidation uses the price aggregator’s post-operation configuration and reports the account as undercollateralized. The attacker keeps the forwarded debt assets, while seizure of the deposited collateral cannot fully repay the minted debt.

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

**File:** contracts/controller/src/strategies/mod.rs (L45-55)
```rust
/// Refreshes listed collateral LTV, checks solvency, health and collateral floor,
/// then persists positions and spoke usage, removes an empty account, and emits
/// the position batch.
pub(crate) fn strategy_finalize(
    env: &Env,
    account_id: u64,
    account: &mut Account,
    cache: &mut Context,
) {
    let _ = enforce_post_pool_solvency(env, cache, account);
    finalize_position_flow(env, account_id, account, cache, PositionSides::Both, true);
```

**File:** contracts/controller/src/risk/totals.rs (L171-206)
```rust
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
```

**File:** docs/reference/invariants.md (L616-624)
```markdown
### INV-FLASH-02 — Protected monetary entry rejects callback reentry

Protected monetary entrypoints reject an active flash guard. Six guarded
windows cover cash flash loans, flash-position funding and callback, router
calls, strategy withdrawal, strategy borrowing and Blend submission. Nested
windows preserve an outer guard.

These windows do not wrap every token call or freeze NFT transfers and public
risk views. A native fixture does not establish callback reachability under
```
