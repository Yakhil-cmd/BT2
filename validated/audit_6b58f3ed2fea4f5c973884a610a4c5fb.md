### Title
Route-selected code can inject unrelated token transfers into a caller’s signed authorization tree - ([File: contracts/controller/src/strategies/swap.rs](contracts/controller/src/strategies/swap.rs))

### Summary
Controller swap strategies treat caller-supplied route bytes as opaque router input while the caller authorizes only the top-level controller invocation. If the configured router invokes attacker-selected pool code, that code can perform `token.transfer(victim, attacker, amount)` beneath the signed controller call. Soroban records this transfer as a child of the victim’s authorization entry; if simulation returns that expanded tree and the victim signs it, the unrelated wallet transfer executes.

The controller’s measured input/output checks bound only the routed `token_in`/`token_out` balances. They do not identify or bound additional token transfers authorized elsewhere in the same invocation tree.

### Finding Description
`swap_collateral` authenticates `caller` and then forwards the caller-controlled `swap` bytes into `withdraw_and_swap_from_supply`. [1](#0-0)  The common swap helper obtains the configured router, authorizes exactly one controller-to-router input transfer, and invokes `router.execute_strategy(&controller, amount_in, swap)`. [2](#0-1)  Afterward it checks only changes in the controller’s input and output token balances. [3](#0-2) 

The authorization helper creates a leaf authorization for only the exact controller input transfer; it does not encode an allowlist of contracts that may run under the router call. [4](#0-3)  Consequently, router- or venue-selected code below that call can request authority directly from the original caller through `from.require_auth()` inside a token transfer. The authorization tree—not the opaque route payload—is what the host enforces.

The harness demonstrates this inconsistency: recording mode attaches a rogue pool’s `wallet_token.transfer(alice, attacker, WALLET_BALANCE)` as a child under Alice’s `swap_collateral` authorization and drains her wallet token. [5](#0-4)  With an honest root-only signed tree, the same transfer is rejected; with the simulation-produced poisoned tree, it succeeds. [6](#0-5) 

### Impact Explanation
An attacker can steal arbitrary token balances held by a victim that are unrelated to the lending position and outside both the declared swap input and output. The loss is limited by what the victim’s signed authorization tree explicitly includes, but the normal simulation workflow can present that extra transfer merely as another child authorization rather than as part of the route’s economic semantics.

This qualifies as theft of user funds. The controller’s accounting remains solvent and its measured swap can even be economically fair, so the theft is not bounded by `amount_in`, route output, collateral value, health factor, or protocol slippage checks.

### Likelihood Explanation
The attacker needs to induce the victim to submit a controller swap route containing attacker-controlled venue code. Reachable entrypoints include `swap_collateral`, `multiply`, `swap_debt`, and `repay_debt_with_collateral`; `swap_collateral` provides the direct path. The victim must sign the authorization tree returned by simulation, including the additional token transfer. Wallets or integrations that summarize only the root operation, expected input transfer, and route result can make this difficult for users to detect, while strict clients that decode every child authorization will reject it.

### Recommendation
Do not let route-selected contracts expand the user’s authority beyond the expected strategy input transfer. Governance should configure only a router that enforces a venue-contract allowlist or cryptographically commits routes to approved venue addresses. At minimum, require routers/venues to reject arbitrary pool addresses and have clients simulate, decode, and display every `AuthorizedInvocation` child before signing; any child token transfer other than the expected strategy input must abort signing. A regression test should assert that a route invoking rogue pool code cannot add an unrelated `token.transfer` beneath the caller’s root authorization.

### Proof of Concept
1. Alice owns a lending account and an unrelated `wallet_token`.
2. The attacker deploys a pool contract whose swap entrypoint executes:
   `wallet_token.transfer(alice, attacker, WALLET_BALANCE)`.
3. Alice submits `swap_collateral(alice, account_id, usdc_hub_asset, amount, eth_hub_asset, malicious_route)`, where the route names the attacker’s pool.
4. The controller authorizes only `USDC.transfer(controller, router, amount)` and calls `execute_strategy`. [7](#0-6) 
5. During router execution, the attacker’s pool calls `wallet_token.transfer(alice, attacker, WALLET_BALANCE)`. Simulation records that transfer as a child of Alice’s `swap_collateral` invocation. [8](#0-7) 
6. If Alice signs only the root invocation without the child, the transaction rolls back; if she signs the simulation-returned tree containing the child, the unrelated wallet token moves to the attacker while the swap itself completes. [6](#0-5)

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

**File:** common/src/token.rs (L33-51)
```rust
/// Authorizes, on behalf of the current contract, one `transfer(from, to, amount)`
/// call on `token_addr` made deeper in the next contract call (for example by
/// the pool). The entry allows no further sub-invocations.
pub fn authorize_transfer_as_current(
    env: &Env,
    token_addr: &Address,
    from: &Address,
    to: &Address,
    amount: i128,
) {
    let entry = InvokerContractAuthEntry::Contract(SubContractInvocation {
        context: ContractContext {
            contract: token_addr.clone(),
            fn_name: symbol_short!("transfer"),
            args: (from.clone(), to.clone(), amount).into_val(env),
        },
        sub_invocations: Vec::new(env),
    });
    env.authorize_as_current_contract(vec![env, entry]);
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
