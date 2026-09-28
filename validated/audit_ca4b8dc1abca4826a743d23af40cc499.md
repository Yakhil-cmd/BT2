### Title
Caller-signed strategy routes can smuggle unauthorized nested token transfers - (File: contracts/controller/src/strategies/swap.rs)

### Summary

A malicious swap route can place third-party contract calls beneath the caller’s authorized `multiply`, `swap_debt`, `swap_collateral`, or `repay_debt_with_collateral` invocation. Although the controller only authorizes one exact transfer of `token_in` from the controller to the configured router, the route itself is caller-controlled and can invoke arbitrary token or venue contracts. Those contracts can issue an additional `transfer` spending the caller’s own wallet balance, and that invocation can be included in the caller-signed authorization tree. The controller’s post-swap accounting checks only the controller’s input/output balances and therefore does not detect unrelated withdrawals from the caller. This is a Soroban analogue of request smuggling: the attacker embeds a second, attacker-benefiting operation inside a request authorized for a different purpose. [1](#0-0) [2](#0-1) 

### Finding Description

`swap_tokens` snapshots the controller’s balances for `token_in` and `token_out`, authorizes exactly one `token_in.transfer(controller, router, amount_in)`, and invokes `router.execute_strategy`. [3](#0-2) 

After the router returns, the function validates only that the controller’s `token_in` balance did not increase, that measured controller spending did not exceed `amount_in`, that unused input is refunded, and that the controller received positive `token_out`. [4](#0-3) 

Those checks do not constrain other token transfers taken from the strategy caller. A route can name third-party contracts, and such a contract can add a token transfer from the caller as a child invocation. If the caller signs the resulting authorization tree, the malicious transfer executes independently of the controller’s measured router input amount. The project’s threat model explicitly notes that a route can put third-party code below the caller’s authorization and that the resulting loss can exceed the routed amount. [2](#0-1) 

The vulnerable route data is reachable through public strategy entrypoints. For example, `multiply` accepts caller-provided `swap` data and passes the borrowed amount plus any debt-denominated initial payment into `swap_tokens_or_passthrough`. [5](#0-4)  The same pattern is used by collateral/debt swaps and repay-with-collateral.

### Impact Explanation

An attacker can steal arbitrary spendable tokens from a user who signs a maliciously constructed strategy authorization tree. The loss is not limited to the declared `amount_in`: a nested token call can transfer other caller-held assets or a larger amount of the same asset directly to the attacker. Because the controller correctly receives the expected swap output and the final account remains solvent, all controller-level accounting checks can pass while the caller’s wallet is drained. This constitutes theft of user funds. [4](#0-3) [2](#0-1) 

### Likelihood Explanation

Likelihood is medium: exploitation requires a user to submit or sign a crafted route whose authorization tree contains the nested malicious transfer. A route-building frontend, bot, copied route payload, or malicious venue integration can produce such a payload. The attacker does not need protocol privileges, leaked keys, compromised infrastructure, or control of the configured router; the route itself reaches arbitrary external contracts. [2](#0-1) 

### Recommendation

Do not expose arbitrary executable route payloads under the caller’s broad strategy authorization. Constrain strategy routes to a typed list of controller-approved venue/token contracts and operation kinds, and reject routes containing any token transfer from the caller other than the operation’s declared funding transfer. At the authorization boundary, display or enforce a canonical invocation tree that contains only the expected strategy entrypoint and expected input transfer. If route flexibility is required, decode and validate every nested invocation before signature generation so callers can reject unexpected child calls. [1](#0-0) [6](#0-5) 

### Proof of Concept

1. Attacker constructs a `multiply` request for victim `V`:
   - `caller = V`
   - nonzero `debt_to_flash_loan`
   - valid listed `debt` and `collateral`
   - caller-controlled `swap` route that:
     - performs enough of a legitimate `debt -> collateral` swap to produce positive controller output;
     - invokes an attacker-controlled venue or token contract that executes `token.transfer(V, attacker, amount)` for an unrelated asset held by `V`.
2. `multiply` collects the account and invokes `borrow_into_controller`, then calls `swap_tokens_or_passthrough` with the controlled route. [7](#0-6) 
3. `swap_tokens` grants only the intended controller-to-router transfer, but invokes the attacker-selected route. [1](#0-0) 
4. The crafted nested contract invokes the extra `transfer` from `V` to the attacker beneath `V`’s signed authorization tree.
5. The router also returns enough legitimate output for the controller balance checks to pass.
6. The controller sees no increase in its input balance, no overspend of `amount_in`, and a positive output delta; the strategy finalizes normally while `V` loses the additional wallet assets. [4](#0-3)

### Citations

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

**File:** docs/explanation/threat-model.md (L154-164)
```markdown
That bound covers the controller's own grant only. The router calls the pool
and token addresses its payload names and keeps no allowlist of them, so a
route can put third-party code on the call stack below the caller's
authorization. A token transfer that such code makes from the caller is
recorded by an honest simulation as a child of the caller's authorization
entry, and it executes if the caller signs that tree. The loss is then the
caller's wallet, not the routed amount, and neither the payload minimum nor the
final risk gate bounds it. An honest swap strategy gives the caller no child
entry, and a direct router swap gives exactly one input transfer. A client must
decode the route it signs and refuse an authorization tree with any other
child. The direct `execute_strategy` path has the same exposure for every swap
```

**File:** contracts/controller/src/strategies/multiply.rs (L76-97)
```rust
    let amount_received = borrow_into_controller(
        env,
        &mut account,
        debt,
        debt_to_flash_loan,
        true,
        PositionAction::Multiply,
        &mut cache,
    );

    let swap_amount_in = amount_received
        .checked_add(debt_extra)
        .unwrap_or_else(|| panic_with_error!(env, GenericError::MathOverflow));

    let swapped_collateral = swap_tokens_or_passthrough(
        env,
        caller,
        &debt.asset,
        swap_amount_in,
        &collateral.asset,
        swap,
    );
```
