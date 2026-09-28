### Title
Unverified route-selected contracts can execute unauthorized token transfers under the caller’s authorization - (File: contracts/controller/src/strategies/swap.rs)

### Summary
The controller accepts an opaque, user-supplied `swap` payload and invokes the configured swap router without validating the identities of the pools or other contracts encoded inside the route. It authorizes only the expected input-token transfer to the router, but contracts reached through the route can perform additional token calls that the Soroban simulation records beneath the caller’s authorization tree. If the caller signs that tree, malicious route-selected code can transfer unrelated wallet assets to an attacker.

### Finding Description
`swap_tokens` decodes no route data itself. It reads the configured router, snapshots the controller’s input/output balances, authorizes exactly one `token_in.transfer(controller, router, amount_in)`, and calls `router.execute_strategy(controller, amount_in, swap)` with the caller-provided bytes [1](#0-0) .

The reachable production entrypoints include `swap_collateral`, `swap_debt`, `repay_debt_with_collateral`, and `multiply`. For example, `swap_collateral` authenticates the account owner/delegate and forwards the opaque `swap` bytes into `withdraw_and_swap_from_supply`, which reaches `swap_tokens` [2](#0-1) .

The router treats venue and pool addresses as payload-controlled registry entries rather than identities bound to a verified venue registry. Each swap hop constructs `pool`, `token_in`, and `token_out` directly from the decoded `assets` registry and dispatches to the selected venue [3](#0-2) . The Aquarius adapter then invokes the payload-selected `pool` address’s `swap` function [4](#0-3) .

The missing verification is the endpoint identity of route-selected code. A contract chosen as a “pool” can satisfy the expected calls while also invoking a token transfer from the caller. During simulation, that nested transfer is attached beneath the caller’s root authorization; if signed, it executes. The repository’s host-level regression test demonstrates this exact authorization-tree behavior for `swap_collateral` [5](#0-4) .

### Impact Explanation
An attacker can steal wallet assets unrelated to the routed `token_in` and unrelated to the victim’s lending collateral. The malicious pool can consume the authorized router input, return enough `token_out` to satisfy the router and controller settlement checks, and additionally call `wallet_token.transfer(victim, attacker, amount)`. Once the victim signs the simulated authorization tree containing that child transfer, the victim’s unrelated wallet token balance is transferred to the attacker.

This is theft of user funds. It is not limited to the declared swap amount because the malicious child transfer can target any token for which the victim’s signed authorization tree authorizes the call.

### Likelihood Explanation
Exploitation requires the victim to submit a malicious route and sign the poisoned authorization tree. An attacker can supply such a route through a compromised or malicious quote source, interface, or off-chain route builder. The route can still produce valid measured output, so the protocol’s balance-delta and final-risk checks do not detect the extra wallet transfer.

The requirement that the user sign the expanded authorization tree reduces the likelihood, but the transaction simulation itself surfaces the malicious transfer as a normal child authorization, making the failure analogous to missing peer/host authentication: the protocol relies on downstream route-selected code without cryptographically or structurally restricting its identity.

### Recommendation
Bind every externally invoked route endpoint to verified venue metadata before execution:

- Maintain an owner-governed venue/pool registry and require every decoded `pool` address to be registered for the selected venue and token pair.
- Alternatively, verify each pool against a trusted factory/registry contract before invoking it.
- Reject routes whose token and pool addresses are not part of an attested pool tuple.
- Ensure route decoding and venue dispatch cannot introduce contracts outside the allowlisted/attested set.
- Emit or expose the complete set of external contract calls expected for a route so clients can reject authorization trees containing unrelated token transfers.

### Proof of Concept
1. Victim owns `account_id` with listed USDC collateral and also holds `WALLET_TOKEN`, an unrelated token.
2. Attacker deploys `RoguePool` configured with `(victim, WALLET_TOKEN, attacker, wallet_balance)`.
3. Attacker constructs a `swap` payload whose hop names `RoguePool` as its pool, USDC as `token_in`, and ETH as `token_out`.
4. Victim calls:

   `controller.swap_collateral(victim, account_id, usdc_hub_asset, 50_000_000_000, eth_hub_asset, malicious_swap)`

5. `swap_collateral` authenticates the victim and forwards the opaque payload to the configured router [2](#0-1) .
6. The router builds the hop pool directly from the payload registry and invokes `RoguePool.swap` [3](#0-2) .
7. Inside `swap`, `RoguePool`:
   - pulls the router-authorized `amount_in`,
   - transfers enough ETH to the router to satisfy measured output,
   - calls `WALLET_TOKEN.transfer(victim, attacker, wallet_balance)`.
8. Simulation records the wallet-token transfer as a child of the victim’s `swap_collateral` authorization. The repository’s test records exactly this tree and balance change [5](#0-4) .
9. When the victim signs that simulated tree, the host accepts the child transfer; the victim’s `WALLET_TOKEN` balance moves to the attacker while the lending swap can still complete normally [6](#0-5) .

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

**File:** contracts/controller/src/strategies/swap_collateral.rs (L40-65)
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
    );
```

**File:** contracts/swap-aggregator/src/execute/mod.rs (L151-166)
```rust
    match op.opcode {
        Opcode::Swap(venue) => {
            let hop = SwapHop {
                pool: ctx.assets.get_unchecked(op.idx_a),
                token_in: ctx.assets.get_unchecked(op.idx_b),
                token_out: ctx.assets.get_unchecked(op.idx_c),
                venue,
            };
            let amount_in = resolve_amount(ctx, vault, op.mode, &hop.token_in, prev);
            if amount_in <= 0 {
                panic_with_error!(ctx.env, Error::InvalidAmount);
            }

            vault.withdraw(&hop.token_in, amount_in);
            let out = venues::dispatch_hop(ctx.env, ctx.router, &hop, amount_in, tokens_cache);
            if out <= 0 {
```

**File:** contracts/swap-aggregator/src/venues/aquarius/pool.rs (L25-34)
```rust
    authorize_token_transfer(env, token_in, router, pool, amount_in);
    let args: Vec<Val> = vec![
        env,
        router.into_val(env),
        in_idx.into_val(env),
        out_idx.into_val(env),
        to_u128(env, amount_in).into_val(env),
        0_u128.into_val(env),
    ];
    let _: u128 = env.invoke_contract(pool, &symbol_short!("swap"), args);
```

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L195-226)
```rust
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
