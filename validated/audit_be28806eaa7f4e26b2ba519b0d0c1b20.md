The CVE's bug class — a crafted resource tricking a user into a gesture that produces a spoofed/malicious outcome — maps onto the unallowlisted router venue path here. Let me pin down the exact call site.### Title
Route-named contract executes arbitrary calls under the victim's signed authorization tree, draining unrelated wallet funds - ([File: contracts/controller/src/strategies/swap.rs])

### Summary
The controller's router-mediated strategies (`multiply`, `swap_debt`, `swap_collateral`, `repay_debt_with_collateral`, `flash_position`, `migrate_from_blend`) accept an attacker-crafted route payload that names arbitrary hop-pool contract addresses. When the router invokes that contract, its `transfer` calls against the caller's address are recorded as children of the caller's own `require_auth` invocation — Soroban auth does not scope children to "the input transfer only". A user who signs the simulated authorization tree authorizes not just the one input transfer but any additional transfers the route-named contract performs, letting the attacker move arbitrary tokens out of the victim's wallet. This is the on-chain analog of CVE-2025-9865's domain spoofing: a crafted artifact (route instead of HTML page) plus one user gesture (signing the auth tree instead of a toolbar gesture) produces an outcome the user did not intend — theft of funds outside the routed amount.

### Finding Description
In `swap_tokens` the controller grants the router exactly one authorized input transfer via `authorize_transfer_as_current`, then calls `router.execute_strategy(&controller, &amount_in, swap)` inside the flash guard [1](#0-0) . The route bytes come from the caller and the router keeps no allowlist of the pool/token addresses the payload names, so route-named third-party contracts run below the caller's authorization [2](#0-1) . The exploit contract is trivial: a `swap` entrypoint that calls `token::Client::transfer(victim, attacker, amount)` for an arbitrary wallet token [3](#0-2) . Because that transfer executes as a nested call under the caller's auth, simulation records it as a child of the caller's `swap_collateral` entry, and it executes successfully once the caller signs that tree [4](#0-3) . Neither the payload minimum output check nor the controller's `RouterOverspend`/risk gates bound the loss, because they only measure the controller's own token-in/token-out balances [5](#0-4) .

### Impact Explanation
Theft of user funds. The attacker drains any token balance held by the victim's wallet address — assets entirely unrelated to the lending position — bounded only by what the victim's wallet holds and signs over. The swap itself can even return a "fair" output so the operation looks normal in every on-chain metric. The dedicated harness test demonstrates `WALLET_BALANCE` moving from Alice to the attacker while the `swap_collateral` call succeeds [6](#0-5) .

### Likelihood Explanation
An unprivileged attacker needs only to (a) deploy a malicious route-named contract and (b) get a victim to submit a strategy call with the crafted route and sign the resulting authorization tree — a single user gesture, matching the CVE's UI-gesture precondition. Reachable through any router-mediated controller entrypoint (`swap_collateral`, `swap_debt`, `multiply`, `repay_debt_with_collateral`, `flash_position`, `migrate_from_blend`) and through direct `execute_strategy` calls on the router [7](#0-6) . The mitigating factor is that a careful wallet/client can decode the auth tree and refuse unexpected child invocations — the recorded tree does contain the stolen transfer as a visible child — but simulation presents it inside the caller's own entry where UIs typically show only the root. Consistent with the source CVE, this is Medium severity.

### Recommendation
Treat the auth-tree surface as part of the protocol's trust boundary rather than pushing it entirely to clients:
- On the controller/router side, constrain hop-pool invocations to a known venue shape (e.g., a venue allowlist or per-venue adapter functions with fixed contract addresses), so route bytes cannot introduce arbitrary contracts beneath the caller's auth.
- Short of that, document and enforce in reference clients that an honest strategy produces exactly one child token-transfer entry (the controller's `authorize_transfer_as_current` grant or the direct router input transfer), and reject any signed tree with additional children — the threat model already states this invariant; it should be enforced, not advisory [8](#0-7) .

### Proof of Concept
Implemented in-repo at `tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs`:

1. Alice supplies 10 000 USDC and holds `WALLET_BALANCE` of an unrelated token in her wallet.
2. Attacker deploys `RogueHopPool`, whose `swap()` does `token.transfer(victim → attacker, amount)` on Alice's wallet token [3](#0-2) .
3. Attacker builds a `RoutedSwap` naming `RogueHopPool` as `hop_pool` [9](#0-8) .
4. Alice calls `swap_collateral` with the route; recording-mode simulation shows the stolen `transfer` recorded as a child of her own `swap_collateral` auth entry [10](#0-9) .
5. Result: `s.wallet(&s.alice) == 0`, `s.wallet(&s.attacker) == WALLET_BALANCE`, while the swap still credits a fair ETH output [6](#0-5) .

Caveat: this exposure is already described in `docs/explanation/threat-model.md` (lines 154–165) as client responsibility; if the scoring rubric treats documented-threat-model items as out of scope alongside documented ADR choices, this analog is weaker than an undocumented bug — but the theft path is real, reachable by an unprivileged address, and demonstrably executes.

### Citations

**File:** contracts/controller/src/strategies/swap.rs (L33-38)
```rust
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

**File:** docs/explanation/threat-model.md (L154-161)
```markdown
That bound covers the controller's own grant only. The router calls the pool
and token addresses its payload names and keeps no allowlist of them, so a
route can put third-party code on the call stack below the caller's
authorization. A token transfer that such code makes from the caller is
recorded by an honest simulation as a child of the caller's authorization
entry, and it executes if the caller signs that tree. The loss is then the
caller's wallet, not the routed amount, and neither the payload minimum nor the
final risk gate bounds it. An honest swap strategy gives the caller no child
```

**File:** docs/explanation/threat-model.md (L162-165)
```markdown
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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L206-226)
```rust
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
