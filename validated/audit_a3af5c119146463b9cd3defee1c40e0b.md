### Title
Attacker-supplied swap route can name arbitrary contract addresses that execute token transfers under the caller's signed authorization tree, draining the victim's wallet - ([File: contracts/controller/src/strategies/swap.rs])

### Summary
CVE-2017-17459 is an argument-injection flaw: a user-controlled hostname beginning with `-` was passed to `ssh` and reinterpreted as a privileged option flag. The analog in XOXNO Lending is the swap-route payload: the `StrategySwap` bytes supplied to `swap_collateral`, `swap_debt`, `multiply`, and `repay_debt_with_collateral` are attacker-controlled data that the router interprets as code — the pool and token addresses it names are invoked on the call stack *below the caller's authorization entry*. A rogue "pool" contract can call `token.transfer(victim, attacker, amount)` for any token in the victim's wallet; in recording mode that transfer is attached as a child of the caller's `require_auth` tree, and in enforcing mode it executes if the victim signs the simulated tree — which standard `simulateTransaction`-then-sign wallets do. The controller only authorizes one exact input transfer to the router; it does not bound what the route's children do once signed.

### Finding Description
`swap_tokens` in `contracts/controller/src/strategies/swap.rs` grants the router exactly one nested authorization — `authorize_transfer_as_current(env, token_in, &controller, &router_addr, amount_in)` — then calls `router.execute_strategy(&controller, &amount_in, swap)` where `swap` is fully caller-supplied XDR [1](#0-0) . The router "keeps no allowlist" of the pool and token addresses its payload names, so a route can put arbitrary third-party code on the call stack under the caller's authorization entry [2](#0-1) . Because the *caller's* `require_auth` (not the controller's) is the root of that tree for direct `execute_strategy` calls — and the controller's strategy auth tree is what the account owner signs for `swap_collateral`/`swap_debt`/`multiply` — any `token.transfer(caller, …)` issued by a payload-named contract joins the caller's signed tree and executes.

This is proven by the protocol's own test: `RogueHopPool::swap` calls `token::Client::transfer(&victim, &to, &amount)` on a wallet token the protocol never listed, the recorded auth tree shows the stolen transfer as a child of Alice's `swap_collateral` entry, and the test asserts `wallet(alice) == 0` and `wallet(attacker) == WALLET_BALANCE` while the swap itself still delivers a fair output [3](#0-2) [4](#0-3) . Neither the payload's `min_out` nor the controller's post-swap risk check bounds the loss, because the theft is orthogonal to the routed amounts [5](#0-4) .

### Impact Explanation
Theft of user funds: an unprivileged attacker who supplies a crafted route to a victim (malicious quote service, phishing front-end, compromised route builder) drains every token the victim holds, including tokens unrelated to the protocol — the loss is the caller's whole wallet, not the routed amount. The swap still produces fair output and the position still passes risk gates, so the transaction looks successful.

### Likelihood Explanation
User-assisted (matching the CVE's UI:R): the victim must sign the poisoned authorization tree. That is exactly what the standard `simulateTransaction` → sign flow produces, since recording mode attaches the rogue transfer under the victim's entry and the wallet presents only the root contract call. Any user who follows a route composed by an attacker — e.g., via a malicious dapp or injected quote — is exposed. No protocol privileges, leaked keys, or oracle manipulation are needed. The threat model itself documents the exposure and places mitigation on the client, i.e., it relies on every integrator correctly rejecting extra auth-tree children — an assumption the on-chain contracts do not enforce.

### Recommendation
Do not rely on clients to police the auth tree. The router/controller should constrain what a route can invoke: maintain an allowlist of venue adapter targets or validate that each hop's pool address is registered for the declared venue (e.g., resolve the pool from the venue's own registry rather than trusting payload-supplied addresses). At minimum, the router should refuse payload token addresses that are not the declared `token_in`/`token_out` of a hop, so a pool contract cannot be induced to touch third-party tokens under the caller's auth. Absent protocol-side enforcement, this remains a documented-but-unmitigated wallet-drain vector reachable through `execute_strategy`, `swap_collateral`, `swap_debt`, `multiply`, and `repay_debt_with_collateral`.

### Proof of Concept
See `tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs`: `UnlistedPoolRouter::execute_strategy` invokes whatever `hop_pool` address the payload names [6](#0-5) ; `RogueHopPool::swap` transfers the victim's unlisted wallet token to the attacker [3](#0-2) ; and `simulation_records_the_rogue_pool_wallet_transfer_under_the_callers_swap_collateral_entry` asserts the stolen transfer is recorded as a child of Alice's signed `swap_collateral` entry and that her wallet balance goes to zero [7](#0-6) .

### Citations

**File:** contracts/controller/src/strategies/swap.rs (L34-38)
```rust
    authorize_transfer_as_current(env, token_in, &controller, &router_addr, amount_in);

    storage::with_flash_guard(env, || {
        let _ = router.execute_strategy(&controller, &amount_in, swap);
    });
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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L62-71)
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
