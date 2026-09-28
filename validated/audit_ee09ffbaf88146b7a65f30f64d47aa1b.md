### Title
Route-selected contracts can expand `swap_collateral` authorization into unrelated wallet-token transfers - (File: contracts/controller/src/strategies/swap.rs)

### Summary

High — A malicious route can place attacker-controlled contract code inside a controller strategy call. That code can request `token::transfer(victim, attacker, amount)` for a token unrelated to the position. Soroban simulation records the request as a child of the victim’s controller authorization, so signing the simulated transaction authorizes both the intended strategy and the unrelated wallet transfer. The controller’s exact input authorization protects only the controller’s `token_in` transfer; it does not bound other authorization children introduced below the signed root call.

### Finding Description

`swap_collateral(caller, account_id, current, amount, new, swap)` is callable by the position owner or an active delegate and accepts caller-supplied route data. After authenticating and authorizing the caller, the strategy withdraws collateral and passes the opaque `swap` payload into `withdraw_and_swap_from_supply` [1](#0-0) .

The shared swap helper sends that payload to the configured router through `router.execute_strategy(&controller, &amount_in, swap)` [2](#0-1) . Before doing so, it grants the router one exact invocation of `token_in.transfer(controller, router, amount_in)` and permits no sub-invocations beneath that grant [3](#0-2) . Afterward, the helper checks only the controller’s input spend, refunds controller-held unused input, and requires positive output [4](#0-3) .

Those checks do not restrict which contracts the route causes the router to invoke and do not inspect authorization requested by those nested contracts. A route-selected pool can therefore call an unrelated token’s `transfer` function with `from = caller`. Because the original `caller.require_auth()` applies to the controller invocation as a rooted authorization tree, simulation can attach that malicious transfer as another child of the same signed controller call rather than treating it as the router’s own narrowly scoped invoker authorization.

The same exposure applies to every unprivileged strategy path that reaches `swap_tokens` or `swap_tokens_or_passthrough`, including `multiply`, `swap_debt`, `swap_collateral`, and `repay_debt_with_collateral`.

### Impact Explanation

A victim who signs the simulated authorization tree loses unrelated wallet assets named by the malicious nested transfer, in addition to performing the expected lending strategy. The stolen asset need not be listed by the lending market, deposited as collateral, or otherwise related to `token_in`, `token_out`, or the account.

This exceeds the accepted route-quality risk: it is not a bad execution price, MEV, or consumption of only the routed amount. It converts one signed strategy operation into authority for an additional token transfer from the signer’s wallet. The theft is permanent once the token transfer succeeds.

### Likelihood Explanation

Exploitation requires the victim to submit a malicious route and sign the authorization tree returned by simulation. This is plausible when routes are produced by an attacker-controlled frontend, quote service, trading bot, or copied transaction payload. The malicious child is syntactically authorized once the victim signs it, so neither the controller’s measured input check nor its output check prevents the unrelated transfer.

The attack does not require privileged access, a leaked protocol key, contract upgrade, oracle manipulation, or control of the victim’s account NFT. The attacker needs only to induce a normal account owner or delegate to execute a crafted strategy route.

### Recommendation

Do not allow route-selected downstream contracts to execute beneath an unconstrained user authorization tree. Maintain a governance-approved allowlist of venue and pool contracts that can be invoked by routed strategies, or otherwise prevent arbitrary contract addresses from being supplied through `StrategySwap`.

Clients should also decode and display every nested authorization before signing, but this should be defense in depth rather than the protocol’s sole protection. The protocol should reject routes naming non-allowlisted callee addresses and should document that measured controller balances do not bound unrelated child authorizations.

### Proof of Concept

1. The victim owns a healthy account with withdrawable USDC collateral.
2. The attacker deploys a contract whose route-facing function executes `unrelated_token.transfer(victim, attacker, victim_balance)`.
3. The attacker constructs a swap payload whose selected venue/pool address is that contract and gives it to the victim as a normal route.
4. The victim simulates and signs:

   `swap_collateral(victim, account_id, USDC_key, amount, ETH_key, malicious_swap)`

5. `process_swap_collateral` authenticates the victim and invokes the swap path [1](#0-0) .
6. `swap_tokens` invokes the configured router with the supplied route payload [2](#0-1) .
7. The route reaches the attacker’s contract, which requests the unrelated `transfer`; simulation records it as an additional child under the victim’s signed controller authorization.
8. The victim signs the returned tree. The unrelated token transfer succeeds even though the controller’s own authorization granted only `USDC.transfer(controller, router, amount)` with no sub-invocations [5](#0-4) .
9. The controller’s post-call checks still pass because they compare only the controller’s `token_in` and `token_out` balances, not unrelated victim-wallet balances [4](#0-3) .

### Citations

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

**File:** contracts/controller/src/strategies/swap.rs (L33-38)
```rust
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
