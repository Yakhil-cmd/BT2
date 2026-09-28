### Title
Opaque swap routes can inject a rogue venue that drains the caller's wallet - (File: contracts/controller/src/strategies/swap.rs)

### Summary
High severity. `swap_collateral`, `swap_debt`, `multiply`, and `repay_debt_with_collateral` accept caller-controlled route bytes, and the controller forwards them to the configured aggregator without decoding or constraining the contracts selected by the route. [1](#0-0) [2](#0-1) [3](#0-2) 

The controller only creates an exact `controller -> router` token-transfer authorization; it does not authorize additional token movement and cannot bound calls that a route-selected contract separately requests under the caller's authorization tree. [4](#0-3) 

### Finding Description
`swap_collateral(caller, account_id, current, amount, new, swap)` is reachable by an unprivileged account owner or delegate, while `swap` is an arbitrary `Bytes` value supplied by the caller's transaction builder. [1](#0-0) [5](#0-4) 

The strategy withdraws collateral and passes the opaque route into the shared swap path. [6](#0-5) 

`swap_tokens` loads the configured router, snapshots the input and output balances, grants the router one exact input transfer, and executes `router.execute_strategy(controller, amount_in, swap)`. [3](#0-2) 

The router interface treats `swap_xdr` as opaque executable route data rather than a controller-validated list of trusted venues. [7](#0-6) 

After the router returns, the controller checks only that it did not overspend its own input and that the output balance increased; neither check prevents a route-selected contract from making an unrelated `caller.require_auth()` request for a token transfer. [8](#0-7) [9](#0-8) 

A malicious route provider can therefore encode a hop through attacker-controlled code that requests a `token::transfer(victim, attacker, amount)` under the victim's signed `swap_collateral` invocation while still arranging a sufficient output balance for the strategy to succeed. [9](#0-8) 

### Impact Explanation
This allows theft of user funds outside the routed amount and outside the victim's lending position. [3](#0-2) 

The controller's own grant remains bounded because `authorize_transfer_as_current` names the token, sender, router, amount, and permits no further sub-invocations. [4](#0-3) 

The unsafe authority is the victim's separate authorization of the top-level strategy call: a poisoned route can add an unrelated wallet-token transfer as a child invocation, and the protocol's positive-output and final-risk checks do not reject that side effect. [9](#0-8) [10](#0-9) 

### Likelihood Explanation
Likelihood is moderate because the attacker cannot call the endpoint as the victim without the victim's authorization. [5](#0-4) 

Exploitation requires the victim to execute a route prepared by an attacker and sign the poisoned authorization tree, but the opaque `Bytes` interface makes venue inspection impractical at the controller boundary and pushes that burden entirely onto route producers and wallet UX. [2](#0-1) [7](#0-6) 

### Recommendation
Do not allow route bytes to name arbitrary executable venue contracts without a protocol-controlled venue registry or decoded manifest of every external contract invocation. [3](#0-2) 

Prefer fixed venue identifiers resolved against an allowlist over raw contract addresses embedded in executable payload bytes, and reject any route whose manifest contains an unexpected contract or token call. [7](#0-6) 

Clients should also simulate the complete lending transaction, decode the route, and reject any caller authorization child beyond the expected calls; an honest `swap_collateral` route does not need an unrelated wallet-token `transfer` beneath the victim's controller authorization. [5](#0-4) [4](#0-3) 

### Proof of Concept
1. The attacker deploys a venue contract whose swap entrypoint hardcodes the victim and executes `token::transfer(victim, attacker, victim_balance)` for a valuable token unrelated to the strategy. [11](#0-10) 

2. The attacker constructs `swap` bytes that route through that malicious venue and provides enough `new.asset` output for the controller's positive-receipt check and the account's final risk checks. [9](#0-8) [10](#0-9) 

3. The victim submits:

```rust
swap_collateral(
    victim,
    account_id,
    current_market,
    amount,
    new_market,
    malicious_swap_bytes,
)
```

The public endpoint accepts the caller-controlled bytes and forwards them through the strategy path. [1](#0-0) 

4. During router execution, the malicious venue invokes the unrelated token transfer from the victim, causing simulation to include that transfer beneath the victim's strategy authorization. [11](#0-10) 

5. If the victim signs the resulting authorization tree, the wallet-token transfer executes, the router can still deliver a valid output, and the lending operation completes while the stolen funds remain with the attacker. [9](#0-8)

### Citations

**File:** contracts/controller/src/lib.rs (L283-302)
```rust
    fn swap_collateral(
        env: Env,
        caller: Address,
        account_id: u64,
        current: HubAssetKey,
        amount: i128,
        new: HubAssetKey,
        swap: Bytes,
    ) {
        strategies::swap_collateral::process_swap_collateral(
            &env,
            &caller,
            SwapCollateralParams {
                account_id,
                current: &current,
                from_amount: amount,
                new: &new,
                swap: &swap,
            },
        );
```

**File:** common/src/types/shared.rs (L9-10)
```rust
/// Encoded swap route passed to the aggregator router's `execute_strategy` entry point.
pub type StrategySwap = Bytes;
```

**File:** contracts/controller/src/strategies/swap.rs (L24-38)
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
```

**File:** contracts/controller/src/strategies/swap.rs (L40-54)
```rust
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
```

**File:** contracts/controller/src/strategies/swap.rs (L74-83)
```rust
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

**File:** contracts/controller/src/strategies/swap_collateral.rs (L40-48)
```rust
    require_authorized_caller(env, caller);

    assert_with_error!(env, current != new, GenericError::AssetsAreTheSame);
    config::require_hub_active(env, current.hub_id);
    require_positive_amount(env, from_amount);

    let mut account = storage::get_account(env, account_id);
    account::require_owner_or_delegate(env, account_id, caller, &account.owner);
    let mut cache = Context::new(env);
```

**File:** contracts/controller/src/strategies/swap_collateral.rs (L55-65)
```rust
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
    );
```

**File:** contracts/controller/src/strategies/swap_collateral.rs (L67-76)
```rust
    let deposit_assets = vec![env, (new.clone(), swapped_amount)];
    supply::process_deposit(
        env,
        &env.current_contract_address(),
        &mut account,
        &deposit_assets,
        &mut cache,
    );

    strategy_finalize(env, account_id, &mut account, &mut cache);
```

**File:** interfaces/swap-aggregator/src/lib.rs (L18-20)
```rust
#[contractclient(name = "SwapAggregatorClient")]
pub trait SwapAggregatorInterface {
    fn execute_strategy(env: Env, sender: Address, total_in: i128, swap_xdr: Bytes) -> i128;
```
