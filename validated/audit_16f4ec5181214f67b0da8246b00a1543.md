### Title

User-controlled swap routes can inject unauthorized token transfers into the caller's signed authorization tree - (File: contracts/controller/src/strategies/swap.rs)

### Summary

`swap_collateral`, `swap_debt`, `repay_debt_with_collateral`, and `multiply` accept caller-supplied opaque route bytes and pass them to the configured router without binding the route to trusted venues or to an authorization-tree shape. The controller protects only its own exact input-token transfer, so a crafted route can place a malicious contract beneath the caller's `require_auth` invocation and cause an unrelated `token.transfer(caller, attacker, amount)` to appear as a signed child authorization.

### Finding Description

The affected entrypoints pass the user-controlled `swap: Bytes` argument into strategy execution, including `swap_collateral` at `contracts/controller/src/lib.rs:283-302`. [1](#0-0) 

`swap_tokens` validates only that `swap` is nonempty and that `amount_in` is positive, then forwards `swap` to `router.execute_strategy` without decoding the route or restricting which contracts the route invokes. [2](#0-1) 

The controller's invoker authorization is limited to one `token.transfer(controller, router, amount_in)` entry with no sub-invocations, so it bounds the controller's token grant but does not prevent route-selected code from requesting additional authority under the caller's original authorization entry. [3](#0-2) 

After the router returns, the controller checks only that its input balance did not gain or overspend and that its output balance increased; neither check limits transfers made from the caller's separate wallet balance. [4](#0-3) 

The result is analogous to crafted-content expression execution: bytes supplied as route data can select executable third-party contract behavior during a security-sensitive operation, rather than being confined to an inert swap description.

### Impact Explanation

An attacker who convinces a position owner to submit a crafted route can make simulation produce a poisoned authorization tree containing a transfer of any token held by the victim, unrelated to the protocol collateral or debt tokens. If the victim signs that tree, the malicious route component can transfer those wallet funds to the attacker while still returning enough swap output for the controller's positive-output and position-risk checks to succeed.

This is theft of user funds outside the intended `amount_in` and is not bounded by the controller's own token grant, unused-input refund, output receipt, or final solvency checks. [4](#0-3) 

### Likelihood Explanation

The attack requires social engineering or a compromised route provider: the victim must submit the crafted `swap` bytes and sign the authorization tree that simulation reports. No privileged protocol role, leaked key, oracle manipulation, or contract upgrade is required, and every strategy entrypoint accepting `swap: Bytes` exposes the same authorization-tree surface.

The controller currently treats route validation as outside its boundary and grants no route-level policy beyond the configured router address. [5](#0-4) 

### Recommendation

Decode and constrain route payloads at the controller boundary, or require the router interface to return a canonical authorization manifest that the caller's client can compare against the simulated authorization tree.

At minimum, enforce an allowlist of permitted venue and pool addresses and reject routes that can produce child invocations outside the expected token transfer for `amount_in`. Wallets and integrations should additionally reject any `swap_collateral`, `swap_debt`, `repay_debt_with_collateral`, or `multiply` authorization containing children other than the expected protocol transfer.

### Proof of Concept

1. The attacker deploys a contract exposing the venue function expected by the route payload.
2. The malicious contract's constructor stores `(victim, wallet_token, attacker, amount)`.
3. Its venue function calls `token::Client::new(wallet_token).transfer(victim, attacker, amount)`.
4. The attacker constructs `swap` bytes that route an otherwise fair swap through that contract.
5. The victim calls `swap_collateral(victim, account_id, current, amount, new, crafted_swap)`.
6. `swap_tokens` forwards the opaque payload to the configured router while authorizing only the controller-to-router input transfer. [6](#0-5) 
7. Transaction simulation reports the malicious wallet-token transfer as a child of the victim's `swap_collateral` authorization.
8. If the victim signs that tree, the attacker receives `amount` of `wallet_token`; the swap can still return a positive output, so `verify_router_output` and the subsequent position checks do not detect the theft. [7](#0-6)

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

**File:** contracts/controller/src/strategies/swap.rs (L13-38)
```rust
pub(crate) fn swap_tokens(
    env: &Env,
    refund_to: &Address,
    token_in: &Address,
    amount_in: i128,
    token_out: &Address,
    swap: &StrategySwap,
) -> i128 {
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

**File:** contracts/controller/src/strategies/swap.rs (L40-55)
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
}
```

**File:** contracts/controller/src/strategies/swap.rs (L74-84)
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
}
```

**File:** common/src/token.rs (L36-51)
```rust
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
