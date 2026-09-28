### Title
Caller-controlled swap routes can smuggle wallet-token theft into the caller’s authorization tree - ([File: contracts/controller/src/strategies/swap.rs](contracts/controller/src/strategies/swap.rs))

### Summary
`swap_collateral`, `swap_debt`, `repay_debt_with_collateral`, and `multiply` accept an opaque `swap: Bytes` payload and pass it to the configured router after authenticating `caller`. [1](#0-0) [2](#0-1)  The controller authorizes only its own exact input transfer to the router, then measures the controller’s token balances after router execution. [3](#0-2) [4](#0-3)  Because the route-selected contracts execute below the caller’s `require_auth` invocation, a malicious route venue can request an additional `token.transfer(victim, attacker, amount)` that simulation records as a child of the victim’s authorization. [5](#0-4) 

### Finding Description
The strongest reachable path is `Controller::swap_collateral(caller, account_id, current, amount, new, swap)`. [1](#0-0)  After `caller.require_auth()` and account-owner/delegate validation, the controller withdraws the selected collateral and passes the caller-supplied `swap` payload to the router. [6](#0-5)  `swap_tokens` loads the configured router, snapshots `token_in` and `token_out`, registers one childless authorization for `token_in.transfer(controller, router, amount_in)`, and invokes `router.execute_strategy(controller, amount_in, swap)`. [7](#0-6)  That invocation scope protects the controller’s input grant, but it does not restrict route-selected venue contracts from adding calls to the caller’s separate authorization tree. [3](#0-2)  Afterward, the controller only rejects input overspending and non-positive output; it does not inspect whether route execution requested unrelated authorizations from `caller`. [8](#0-7) 

### Impact Explanation
A malicious route can transfer an unrelated wallet asset from the swap caller to an attacker while still returning enough `token_out` to satisfy the controller’s positive-output and final-risk checks. [9](#0-8) [10](#0-9)  The stolen asset need not be either swap token and need not be listed by the lending protocol, so the loss can exceed the routed collateral amount. [1](#0-0) [11](#0-10)  This is theft of user funds rather than a pricing or route-quality loss, although exploitation requires the victim to sign the poisoned authorization tree produced by simulation. [2](#0-1) 

### Likelihood Explanation
The route and its venue addresses are attacker-controlled data, while any unprivileged account owner can reach `swap_collateral` for their own account. [1](#0-0) [12](#0-11)  The attacker cannot steal from an arbitrary victim without that victim signing the transaction, but a crafted strategy route can make the theft appear as an authorization child during simulation. [2](#0-1) [5](#0-4)  The same pattern applies to every controller strategy that forwards `swap` bytes to the router. [13](#0-12) [14](#0-13) 

### Recommendation
Restrict executable route venues and pool addresses to a protocol-controlled allowlist or verified venue registry instead of trusting arbitrary addresses encoded in `swap`. [15](#0-14)  Until route targets are constrained, wallets and integrating clients must decode the route and reject any authorization tree containing calls other than the expected strategy invocation and its legitimate token transfer. [16](#0-15)  The controller should also document that its balance checks do not bound side effects requested from the caller during nested route execution. [8](#0-7) 

### Proof of Concept
1. Alice owns a lending account with USDC collateral and also holds an unrelated token in her wallet. [12](#0-11) 
2. An attacker deploys a contract exposing the venue ABI expected by the route and configures it to call `unrelated_token.transfer(alice, attacker, alice_balance)`. [5](#0-4) 
3. The attacker gives Alice a `swap` payload that routes through that venue and otherwise returns a positive amount of the requested collateral asset. [17](#0-16) 
4. Alice calls `swap_collateral(alice, account_id, usdc_key, amount, eth_key, malicious_swap)`. [1](#0-0) 
5. Transaction simulation records the malicious wallet transfer as a child beneath Alice’s `swap_collateral` authorization; signing that tree makes the nested transfer valid. [2](#0-1) 
6. The controller sees a positive measured ETH receipt and a solvent final account, so the strategy succeeds while Alice’s unrelated wallet token is transferred to the attacker. [17](#0-16) [10](#0-9)

### Citations

**File:** interfaces/controller/src/lib.rs (L98-106)
```rust
    fn swap_collateral(
        env: Env,
        caller: Address,
        account_id: u64,
        current: HubAssetKey,
        amount: i128,
        new: HubAssetKey,
        swap: Bytes,
    );
```

**File:** contracts/controller/src/risk/validation.rs (L13-15)
```rust
pub(crate) fn require_authorized_caller(env: &Env, caller: &Address) {
    caller.require_auth();
    require_not_flash_loaning(env);
```

**File:** common/src/token.rs (L33-51)
```rust
/// Authorizes, on behalf of the current contract, one `transfer(from, to, amount)`
/// call on `token_addr` made deeper in the next contract call (for example by
/// the pool). The entry allows no further sub-invocations.
pub fn authorize_transfer_as_current(
    env: &Env,
    token_addr: &Address,
    from: &Address,
    to: &Address,
    amount: i128,
) {
    let entry = InvokerContractAuthEntry::Contract(SubContractInvocation {
        context: ContractContext {
            contract: token_addr.clone(),
            fn_name: symbol_short!("transfer"),
            args: (from.clone(), to.clone(), amount).into_val(env),
        },
        sub_invocations: Vec::new(env),
    });
    env.authorize_as_current_contract(vec![env, entry]);
```

**File:** contracts/controller/src/strategies/swap.rs (L24-83)
```rust
    let controller = env.current_contract_address();
    let router_addr = storage::get_swap_aggregator(env);
    let router = SwapAggregatorClient::new(env, &router_addr);
    let token_in_client = token::Client::new(env, token_in);

    // Snapshot before router execution to measure its spend and output.
    let in_before = token_in_client.balance(&controller);
    let out_before = token::Client::new(env, token_out).balance(&controller);

    // Authorize only this token transfer to this router for this exact amount.
    authorize_transfer_as_current(env, token_in, &controller, &router_addr, amount_in);

    storage::with_flash_guard(env, || {
        let _ = router.execute_strategy(&controller, &amount_in, swap);
    });

    // Reject input gains or overspending; refund only this swap's unused input.
    let in_after = token_in_client.balance(&controller);
    assert_with_error!(env, in_after <= in_before, StrategyError::RouterOverspend);
    let actual_spent = in_before - in_after;
    assert_with_error!(
        env,
        actual_spent <= amount_in,
        StrategyError::RouterOverspend
    );
    let leftover = amount_in - actual_spent;
    if leftover > 0 {
        token_in_client.transfer(&controller, refund_to, &leftover);
    }

    verify_router_output(env, token_out, out_before)
}

/// Passes matching assets through only with an empty route; otherwise swaps.
pub(crate) fn swap_tokens_or_passthrough(
    env: &Env,
    refund_to: &Address,
    token_in: &Address,
    amount_in: i128,
    token_out: &Address,
    swap: &StrategySwap,
) -> i128 {
    if token_in == token_out {
        assert_with_error!(env, swap.is_empty(), GenericError::InvalidPayments);
        amount_in
    } else {
        swap_tokens(env, refund_to, token_in, amount_in, token_out, swap)
    }
}

/// Returns the output balance increase; rejects zero or negative receipts.
fn verify_router_output(env: &Env, token_out: &Address, balance_before: i128) -> i128 {
    let received = balance_delta_since(
        env,
        token_out,
        &env.current_contract_address(),
        balance_before,
    );
    assert_with_error!(env, received > 0, StrategyError::NoSwapOutput);
    received
```

**File:** contracts/controller/src/strategies/swap_collateral.rs (L40-64)
```rust
    require_authorized_caller(env, caller);

    assert_with_error!(env, current != new, GenericError::AssetsAreTheSame);
    config::require_hub_active(env, current.hub_id);
    require_positive_amount(env, from_amount);

    let mut account = storage::get_account(env, account_id);
    account::require_owner_or_delegate(env, account_id, caller, &account.owner);
    let mut cache = Context::new(env);
    // Check the destination before withdrawing existing collateral.
    require_can_supply(env, &mut cache, account.spoke_id, new);

    let extra_assets = vec![env, current.asset.clone(), new.asset.clone()];
    prefetch_strategy_prices(&mut cache, &account, &extra_assets);

    let swapped_amount = withdraw_and_swap_from_supply(
        env,
        &mut account,
        &mut cache,
        caller,
        current,
        from_amount,
        &new.asset,
        swap,
        events::PositionAction::SwColWd,
```

**File:** contracts/controller/src/strategies/mod.rs (L48-55)
```rust
pub(crate) fn strategy_finalize(
    env: &Env,
    account_id: u64,
    account: &mut Account,
    cache: &mut Context,
) {
    let _ = enforce_post_pool_solvency(env, cache, account);
    finalize_position_flow(env, account_id, account, cache, PositionSides::Both, true);
```

**File:** contracts/controller/src/strategies/swap_debt.rs (L65-72)
```rust
    let repay_amount = swap_tokens_or_passthrough(
        env,
        caller,
        &new_debt.asset,
        amount_received,
        &existing_debt.asset,
        swap,
    );
```

**File:** contracts/controller/src/strategies/repay_debt_with_collateral.rs (L108-118)
```rust
    let debt_available = withdraw_and_swap_from_supply(
        env,
        account,
        cache,
        caller,
        collateral,
        collateral_amount,
        &debt.asset,
        swap,
        events::PositionAction::RpColWd,
    );
```
