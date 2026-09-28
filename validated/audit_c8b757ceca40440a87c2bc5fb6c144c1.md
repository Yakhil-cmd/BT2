### Title
Arbitrary route execution can add unauthorized wallet transfers to a signed strategy transaction - (File: contracts/controller/src/strategies/swap.rs)

### Summary
The controller forwards caller-supplied `swap` bytes to the configured aggregator and validates only the controller’s measured input spend, output receipt, and final position risk. Because strategy entrypoints authenticate the account caller before traversing route-selected external venues, a malicious venue in an attacker-supplied route can request additional token transfers from that caller. If the victim signs the authorization tree produced by simulation, funds unrelated to the lending position can be stolen. [1](#0-0) 

### Finding Description
`swap_collateral`, `swap_debt`, `repay_debt_with_collateral`, and `multiply` accept route bytes as ordinary caller-controlled arguments. For example, `swap_collateral` authenticates `caller`, verifies ownership or delegation, withdraws collateral, and passes the supplied route into the swap path. [2](#0-1) 

The router boundary authorizes one controller-to-router transfer and invokes `execute_strategy` with the unmodified `swap` payload. [3](#0-2)  Afterward, the controller checks only that the controller did not gain input, spent no more than `amount_in`, and received positive output. [4](#0-3) 

Those checks do not constrain code invoked by route-selected venues. A malicious venue can execute below the router and request a token transfer whose `from` is the original account caller. In Soroban’s authorization model, that request is represented as a child of the caller’s root strategy authorization. The controller’s balance checks cannot observe or reject this side transfer because it is neither controller input nor output. Finalization only checks the account’s post-operation risk before persistence. [5](#0-4) 

### Impact Explanation
An attacker can steal arbitrary SAC/token balances held by the account owner, including assets not listed by the protocol and unrelated to the strategy’s `token_in`. The malicious route can still return a positive output that leaves the lending position solvent, so every controller-level accounting check succeeds while the extra wallet transfer executes.

This is theft of user funds. The loss is bounded by the caller’s token balances and by what the victim authorizes, not by the routed collateral amount.

### Likelihood Explanation
The attacker needs no protocol privilege. They need the victim or its client to submit a controller strategy containing attacker-selected route bytes and then sign the simulated authorization tree. The route itself can satisfy the protocol’s measured-output and final-risk requirements, making the harmful transfer dependent on whether the wallet or user inspects and rejects the additional authorization child.

### Recommendation
Restrict routes to governance-approved venue/pool contracts rather than permitting arbitrary route-selected code under the account caller’s authorization. If arbitrary venues must remain supported, introduce an authorization-isolating strategy execution model so downstream calls cannot request additional authority from the account owner. Clients should also reject any simulated authorization tree containing transfers beyond the explicitly expected strategy transfers, but wallet-side review should not be the only defense.

### Proof of Concept
1. Deploy a malicious contract exposing the venue interface expected by the configured router.
2. Configure its `swap` behavior to call an unrelated token’s `transfer(victim, attacker, victim_balance)` before returning normally.
3. Construct a valid `swap_collateral` route that passes through this malicious venue while still returning enough `new.asset` for the account to remain solvent.
4. Have the victim call:

   ```text
   swap_collateral(
       caller = victim,
       account_id = victim_account,
       current = listed_current_collateral,
       amount = collateral_amount,
       new = listed_new_collateral,
       swap = malicious_route_bytes
   )
   ```

5. Simulation produces a root `swap_collateral` authorization containing an additional child invocation:
   `unrelated_token.transfer(victim, attacker, victim_balance)`.
6. If the victim signs that tree, the malicious venue transfer executes. The controller observes only bounded input spending, positive output receipt, and a solvent final account; it does not detect the stolen unrelated token.

### Citations

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
