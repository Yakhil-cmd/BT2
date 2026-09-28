### Title
Crafted swap routes can inject unauthorized token transfers into the caller’s authorization tree - ([File: contracts/controller/src/strategies/swap.rs](https://github.com/Camomtat/rs-lending-xlm--016/blob/main/contracts/controller/src/strategies/swap.rs))

### Summary
A route supplied to `swap_collateral`, `swap_debt`, `multiply`, or `repay_debt_with_collateral` can name attacker-controlled venue contracts. Because the router invokes those route-selected contracts beneath the caller’s authorized invocation, a malicious venue can request an unrelated `token.transfer(caller, attacker, amount)` and have it recorded as an authorization-tree child; if the victim signs the simulated tree, the transfer executes even though the lending operation itself remains solvent.

### Finding Description
`swap_collateral` authenticates `caller`, verifies account ownership or delegation, and forwards the caller-controlled opaque `swap` bytes into the swap path. The controller authorizes only one exact input transfer to the configured router, then invokes `router.execute_strategy(controller, amount_in, swap)`; it does not inspect or constrain the route’s pool/venue addresses. The router decodes the payload, resolves `hop.pool` from the user-supplied asset registry, and dispatches the selected venue. Venue adapters invoke the supplied pool address directly—for example, the Soroswap adapter calls `get_reserves` and `swap` on `hop.pool`. A malicious contract implementing those functions can therefore run beneath the authorized route and issue a token transfer requiring the original caller’s authorization. Soroban records this as a child of that caller’s signed invocation; simulation surfaces it and an enforcing transaction accepts it if the signed tree contains the child.

### Impact Explanation
This permits theft of arbitrary wallet tokens held by the victim, including assets unrelated to the lending position. The malicious route can still return sufficient output so the account’s post-swap collateral and health checks pass. The proof test demonstrates Alice’s entire unlisted wallet-token balance moving to an attacker while the requested collateral swap succeeds.

### Likelihood Explanation
The attacker must convince the victim to execute a crafted route, such as through a malicious quote or frontend, and the victim must sign the authorization tree containing the injected child. This requires victim approval, but the swap bytes are opaque and the injected transfer is reachable without privileged protocol access, leaked keys, upgraded code, or control of a listed token.

### Recommendation
Constrain route execution to governance-approved pool contracts, or add an authenticated route registry/hash so payloads cannot designate arbitrary venues. If arbitrary venues remain intentional, enforce a client-side invariant that a lending strategy authorization has no caller child invocations beyond the expected token pull, and surface decoded route venues before signing. The contract cannot itself prevent the victim from explicitly signing a malicious child transfer, so deployment should pair venue restrictions with mandatory authorization-tree verification.

### Proof of Concept
1. Deploy a contract exposing the expected venue functions, such as `get_reserves` and `swap`.
2. In `swap`, call `token::Client::transfer(victim, attacker, wallet_balance)` for an unrelated token held by the victim.
3. Encode a valid route whose `pool` address is that contract and whose output/minimum causes the swap to return a valid amount.
4. Have the victim invoke `swap_collateral(caller, account_id, current, amount, new, swap)` using that route.
5. During simulation, the malicious transfer appears as a child of the victim’s `swap_collateral` authorization; submitting the signed tree transfers the victim’s unrelated tokens while the collateral swap completes. The repository’s focused test shows the recorded child and resulting balance movement. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

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

**File:** contracts/swap-aggregator/src/execute/mod.rs (L152-166)
```rust
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

**File:** contracts/swap-aggregator/src/venues/soroswap.rs (L55-88)
```rust
    let (reserve_0, reserve_1): (i128, i128) = ctx.env.invoke_contract(
        &ctx.hop.pool,
        &Symbol::new(ctx.env, "get_reserves"),
        no_args,
    );
    let (reserve_in, reserve_out) = if token_in_is_0 {
        (reserve_0, reserve_1)
    } else {
        (reserve_1, reserve_0)
    };

    let requested_out = soroswap_amount_out(ctx.env, ctx.amount_in, reserve_in, reserve_out);
    if requested_out <= 0 {
        panic_with_error!(ctx.env, Error::ZeroOutput);
    }

    let token_client = token::Client::new(ctx.env, &ctx.hop.token_in);
    token_client.transfer(ctx.router, &ctx.hop.pool, &ctx.amount_in);

    let (amount_0_out, amount_1_out) = if token_in_is_0 {
        (0_i128, requested_out)
    } else {
        (requested_out, 0_i128)
    };
    let args: Vec<Val> = vec![
        ctx.env,
        amount_0_out.into_val(ctx.env),
        amount_1_out.into_val(ctx.env),
        ctx.router.into_val(ctx.env),
    ];
    let _: () = ctx
        .env
        .invoke_contract(&ctx.hop.pool, &symbol_short!("swap"), args);
}
```
