### Title
Malicious swap-route venue can steal unrelated tokens through the caller's signed authorization tree - (File: contracts/controller/src/strategies/swap.rs)

### Summary
An attacker can embed an attacker-controlled pool address in the `swap` payload passed to `swap_collateral`, `multiply`, `swap_debt`, or `repay_debt_with_collateral`. The controller forwards that opaque route to the configured router, and the router invokes whichever pool address the route specifies. [1](#0-0) [2](#0-1) 

The malicious pool can call `token.transfer(victim, attacker, amount)` during the venue call. Soroban simulation records that additional authorization request as a child of the victim's top-level controller authorization; if the victim signs the resulting tree, the unrelated wallet-token transfer executes even though the lending operation itself settles correctly. [3](#0-2) 

### Finding Description
`swap_collateral` accepts caller-provided `swap: Bytes` and authenticates only the owner or delegate for `account_id`; it does not inspect or restrict venue addresses inside the route. [4](#0-3) [5](#0-4) 

`swap_tokens` authorizes only the controller's exact input transfer to the configured router and then invokes `router.execute_strategy(controller, amount_in, swap)`. [6](#0-5) 

The router decodes user-controlled `assets` and `ops`, reads the hop's `pool`, `token_in`, and `token_out` from that registry, and dispatches the selected venue without checking the pool against an allowlist. [7](#0-6) [2](#0-1) 

For example, the Soroswap adapter invokes `get_reserves` and `swap` on `hop.pool`; either callback can contain attacker code. [8](#0-7) [9](#0-8) 

Measured input/output checks constrain routed balances, but they do not prevent the selected code from making an unrelated `require_auth`-protected call against the transaction's original caller. [10](#0-9) 

The repository's authorization regression test demonstrates that simulation records the rogue pool's `wallet_token.transfer(alice, attacker, balance)` beneath Alice's `swap_collateral` invocation, and that signing that tree transfers her entire unrelated-token balance while the intended swap output is deposited. [3](#0-2) [11](#0-10) 

### Impact Explanation
This is theft of user funds: a victim executing an otherwise valid lending strategy can lose arbitrary SEP-41/Stellar-asset tokens that are unrelated to the swap and never deposited in the protocol. [11](#0-10) 

The attack does not depend on stealing the routed input or producing a bad output; the malicious venue can pay the full expected output, satisfy the router's measured-output checks, and leave the resulting lending account solvent. [12](#0-11) [13](#0-12) 

### Likelihood Explanation
An unprivileged attacker can deploy a compatible venue contract, craft a route referencing it, and present the strategy for the victim to sign; no governance role, leaked key, upgrade, or protocol privilege is required. [2](#0-1) [14](#0-13) 

Exploitation requires the victim to sign the expanded authorization tree containing the extra token transfer, so wallets and clients that display and enforce an expected-child whitelist prevent the loss. [15](#0-14) 

Because the additional authorization can be discovered only by decoding and inspecting the simulated authorization tree, route marketplaces, quote providers, or wallet UX that do not surface nested invocations make the attack realistic. [16](#0-15) 

### Recommendation
Maintain a governance-controlled allowlist of venue/pool contract addresses and reject routes whose `hop.pool` is absent, rather than treating arbitrary route-selected contracts as interchangeable ABI implementations. [2](#0-1) 

Until that exists, clients must simulate the exact transaction, decode every `SorobanAuthorizedInvocation` subtree, and reject any authorization entry beyond the expected controller operation and exact token pulls. [16](#0-15) 

### Proof of Concept
1. Deploy a malicious contract implementing the Soroswap pair ABI: `get_reserves()` returns sufficient reserves, and `swap(amount_0_out, amount_1_out, to)` transfers a fair `token_out` amount to the router and additionally calls `unrelated_token.transfer(victim, attacker, victim_balance)`. [14](#0-13) 

2. Construct a swap payload whose asset registry contains the malicious pool as `idx_a`, the supplied collateral token as `idx_b`, and the desired collateral token as `idx_c`, with a positive minimum output. [2](#0-1) 

3. Have the victim invoke `Controller.swap_collateral(caller=victim, account_id, current, amount, new, malicious_swap)`. [4](#0-3) 

4. The controller withdraws the victim's existing collateral to itself and calls the configured router with the malicious payload. [17](#0-16) [1](#0-0) 

5. The router invokes the malicious pool; simulation records the pool's unrelated-token transfer as a child of the victim's `swap_collateral` authorization. [18](#0-17) 

6. If the victim signs that returned tree, the malicious transfer succeeds, the venue's fair output satisfies the measured-output check, and the victim loses the unrelated wallet balance while receiving the expected strategy collateral. [11](#0-10)

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

**File:** contracts/swap-aggregator/src/execute/mod.rs (L58-66)
```rust
    let StrategyPayload {
        amounts,
        assets,
        ops,
    } = payload;
    let program = Program::decode(&env, &ops, assets.len(), amounts.len());

    let input_token = assets.get_unchecked(program.token_in);
    let output_token = assets.get_unchecked(program.token_out);
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

**File:** contracts/controller/src/lib.rs (L280-301)
```rust
    /// Withdraws `amount` of `current`, converts it to `new` via `swap` and
    /// redeposits the proceeds. Requires owner or delegate authorization.
    #[when_not_paused]
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
```

**File:** contracts/controller/src/strategies/swap_collateral.rs (L40-48)
```rust
    require_authorized_caller(env, caller);

    assert_with_error!(env, current != new, GenericError::AssetsAreTheSame);
    config::require_hub_active(env, current.hub_id);
    require_positive_amount(env, from_amount);

    let mut account = storage::get_account(env, account_id);
    account::require_owner_or_delegate(env, account_id, caller, &account.owner);
    let mut cache = Context::new(env);
```

**File:** contracts/controller/src/strategies/swap_collateral.rs (L55-76)
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

    let deposit_assets = vec![env, (new.clone(), swapped_amount)];
    supply::process_deposit(
        env,
        &env.current_contract_address(),
        &mut account,
        &deposit_assets,
        &mut cache,
    );

    strategy_finalize(env, account_id, &mut account, &mut cache);
```

**File:** contracts/swap-aggregator/src/venues/soroswap.rs (L54-87)
```rust
    let no_args: Vec<Val> = vec![ctx.env];
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
```

**File:** contracts/swap-aggregator/src/venues/mod.rs (L30-56)
```rust
    let ctx = HopContext::new(env, router, hop, amount_in);
    let before_in = ctx.input_balance();
    let before_out = ctx.output_balance();

    match hop.venue {
        SwapVenue::Soroswap => soroswap::swap(&ctx),
        SwapVenue::Aquarius => aquarius::swap(&ctx, tokens_cache),
        SwapVenue::Phoenix => phoenix::swap(&ctx),
        SwapVenue::Sushi => sushi::swap(&ctx),
        SwapVenue::CometDex => comet::swap(&ctx),
    };

    let received = ctx
        .output_balance()
        .checked_sub(before_out)
        .unwrap_or_else(|| panic_with_error!(env, Error::ZeroOutput));
    if received <= 0 {
        panic_with_error!(env, Error::ZeroOutput);
    }

    let after_in = ctx.input_balance();
    let spent = before_in
        .checked_sub(after_in)
        .unwrap_or_else(|| panic_with_error!(env, Error::InvalidAmount));
    if spent != amount_in {
        panic_with_error!(env, Error::InvalidAmount);
    }
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
