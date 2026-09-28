### Title
Attacker-controlled swap routes can inject wallet-draining calls into the caller authorization tree - (File: contracts/controller/src/strategies/swap.rs)

### Summary
The controller accepts opaque route bytes in `multiply`, `swap_debt`, `swap_collateral`, and `repay_debt_with_collateral`, then forwards them to the configured swap router without interpreting or restricting the encoded route. A crafted route can cause route-selected code to request an additional token transfer from the caller while the strategy call is being simulated; if the caller signs the resulting authorization tree, the injected transfer executes. This is analogous to interpreting a user-controlled command string without constraining the commands it may contain.

### Finding Description
`StrategySwap` is defined as opaque `Bytes` representing the encoded swap-router payload. [1](#0-0) 

The `swap_collateral` entrypoint accepts caller-supplied `swap` bytes. [2](#0-1) 

The strategy authenticates only the `caller` and verifies ownership or delegated control of the target account. [3](#0-2) 

It then passes the same bytes into `withdraw_and_swap_from_supply`, ultimately reaching `swap_tokens`. [4](#0-3) 

`swap_tokens` checks only that the route is non-empty, authorizes the exact controller-to-router input transfer, invokes `execute_strategy`, and afterward checks the controller's input and output balances. [5](#0-4) 

Those checks do not parse the route, enumerate the contracts it can invoke, or limit the authorization-tree side effects those contracts can request. [6](#0-5) 

Because the strategy begins with `caller.require_auth`, authorization is represented by the caller's signed invocation tree rather than by a single isolated token approval. [7](#0-6) 

A malicious route can therefore place a route-selected contract on the call stack and have that contract attempt `token.transfer(caller, attacker, amount)`; simulation records the attempted call as an additional child beneath the caller's controller authorization. If the wallet or client signs that tree instead of rejecting the unexpected child, the malicious venue receives both the authorized controller invocation and the unrelated wallet transfer.

### Impact Explanation
A successful attack steals token balances directly from the user's wallet, outside the collateral amount intentionally routed through the strategy. The controller's measured-output and post-action solvency checks protect protocol accounting but do not prevent an unrelated token transfer authorized as a child invocation. Affected entrypoints include `multiply`, `swap_debt`, `swap_collateral`, and `repay_debt_with_collateral`.

### Likelihood Explanation
Exploitation requires the victim to submit a malicious `swap` payload and sign an authorization tree containing the injected token transfer. This is plausible when routes are supplied by an external quote service, application, plug-in, or agent and the wallet does not clearly display nested contract invocations. A malicious route producer can deploy the hostile venue and return a fair output so the transaction still satisfies the route minimum and the controller's measured receipt checks.

### Recommendation
Do not rely on balance checks alone to bound route execution. Decode and validate the swap payload before submission, reject routes containing unexpected pool, token, or venue addresses, and require the simulated authorization tree to contain only the expected nested transfer. Preferably constrain router-dispatched venues to a protocol-maintained allowlist or route-format registry so an arbitrary contract cannot execute beneath the caller's controller authorization.

### Proof of Concept
1. Deploy a malicious contract exposing the pool/swap function expected by the router. In that function, call `token.transfer(victim, attacker, victim_balance)` for an unrelated token held by the victim.
2. Construct a valid `StrategySwap` whose route selects the malicious contract as a hop venue while still returning enough of the requested output token to satisfy the router minimum.
3. Prompt the victim to submit:

```text
swap_collateral(
    caller = victim,
    account_id = victim_account,
    current = listed_collateral,
    amount = collateral_amount,
    new = listed_output_asset,
    swap = malicious_route_bytes
)
```

4. During simulation, the malicious venue's `transfer(victim, attacker, victim_balance)` appears as an additional child under the victim's `swap_collateral` authorization.
5. If the victim signs the poisoned tree, the controller swap succeeds and the unrelated token transfer also succeeds, leaving the attacker with the victim's wallet funds.

### Citations

**File:** common/src/types/shared.rs (L9-10)
```rust
/// Encoded swap route passed to the aggregator router's `execute_strategy` entry point.
pub type StrategySwap = Bytes;
```

**File:** contracts/controller/src/lib.rs (L283-301)
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
```

**File:** contracts/controller/src/strategies/swap_collateral.rs (L40-47)
```rust
    require_authorized_caller(env, caller);

    assert_with_error!(env, current != new, GenericError::AssetsAreTheSame);
    config::require_hub_active(env, current.hub_id);
    require_positive_amount(env, from_amount);

    let mut account = storage::get_account(env, account_id);
    account::require_owner_or_delegate(env, account_id, caller, &account.owner);
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

**File:** contracts/controller/src/strategies/swap.rs (L21-38)
```rust
    require_positive_amount(env, amount_in);
    assert_with_error!(env, !swap.is_empty(), GenericError::InvalidPayments);

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

**File:** contracts/controller/src/risk/validation.rs (L12-16)
```rust
/// Authenticates `caller` and rejects execution during a flash loan.
pub(crate) fn require_authorized_caller(env: &Env, caller: &Address) {
    caller.require_auth();
    require_not_flash_loaning(env);
}
```
