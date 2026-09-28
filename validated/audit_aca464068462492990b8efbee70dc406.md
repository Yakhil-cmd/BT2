### Title
Attacker-crafted `swap` bytes execute arbitrary third-party contract code inside the caller's signed auth tree, draining the caller's wallet - (File: contracts/controller/src/strategies/swap.rs)

### Summary
The deserialization bug class (CWE-502: untrusted serialized input drives execution) maps onto the controller's strategy `swap: Bytes` parameter. `swap_collateral`, `swap_debt`, `repay_debt_with_collateral`, `multiply`, and `migrate_from_blend` accept caller-supplied serialized route bytes and pass them verbatim to the swap router via `swap_tokens` [1](#0-0) . The decoded route names the token and pool addresses it invokes, and neither the controller nor the router keeps a venue/pool allowlist [2](#0-1) . A route can therefore put arbitrary contract code on the call stack beneath the caller's `require_auth` entry, and any `token.transfer(caller → attacker)` that code performs is recorded as a child of the caller's signed authorization tree and executes [3](#0-2) .

### Finding Description
`swap_tokens` grants the router exactly one `token_in.transfer(controller, router, amount_in)` invocation and then calls `router.execute_strategy(&controller, &amount_in, swap)` with the raw caller-provided bytes [4](#0-3) . Inside the router, `execute_strategy` decodes `swap_xdr` into a `StrategyPayload` whose `ops` byte stream is a program: each 5-byte instruction record selects a pool address from the attacker-controlled `assets` registry, and `venues::dispatch_hop` calls it [5](#0-4) . Because the venue set is not allowlisted, the payload's named "pool" can be an attacker contract. When that contract calls `token::transfer(alice, attacker, alice_balance)` on some token Alice holds, the host records it as a sub-invocation of Alice's `swap_collateral` auth entry; the transaction simulates successfully, and if Alice signs the tree the simulator produced, the transfer executes. The harness test demonstrates this end-to-end: a rogue hop pool moves Alice's entire wallet-token balance to the attacker while the swap itself still produces fair output and all risk gates pass [6](#0-5) .

### Impact Explanation
Theft of user funds. The loss is not bounded by the routed amount, the payload `min_out`, or the final account risk gates: the rogue contract can transfer any token the signing address holds, in any amount, because the transfer executes under the victim's own authorization [7](#0-6) . The enforced-mode test confirms that signing the simulator-produced tree moves `WALLET_BALANCE` from Alice to the attacker [8](#0-7) .

### Likelihood Explanation
Reachable by an unprivileged attacker who serves or convinces a user to submit a poisoned `swap` route (e.g., via a malicious quote source or crafted `routeXdr`). The victim need only sign the authorization tree the simulation returns; honest wallets that do not decode and diff the child invocations will sign it, since an honest route legitimately produces a non-empty auth tree and the rogue transfer is structurally a normal child entry [9](#0-8) . The same exposure exists on the direct `execute_strategy` path for every swap user [10](#0-9) . Severity: High (full wallet drain, but requires the victim to sign a poisoned route).

### Recommendation
On-chain mitigation is limited because Soroban auth is caller-signed, but the protocol can reduce the surface: (1) maintain a governance-managed venue/pool allowlist checked either in the controller before invoking the router or in `dispatch_hop` before calling a payload-named pool, analogous to the Blend-pool approval used for `migrate_from_blend` [11](#0-10) ; (2) document and enforce in the SDK/wallet path that any auth tree for a strategy call containing a child invocation not authored by the controller (i.e., anything other than the single input `transfer` the user expects) must be rejected, as `threat-model.md` prescribes [12](#0-11) .

### Proof of Concept
1. Attacker deploys `RogueHopPool`, a contract that answers the venue calls the adapter makes but, during execution, calls `token::Client::transfer(alice, attacker, wallet_balance)` on an unrelated token Alice holds.
2. Attacker crafts a `StrategyPayload` whose `assets` registry lists `RogueHopPool` as the pool for a hop, encodes it as `swap_xdr`, and gets it to Alice (malicious quote response / phishing route).
3. Alice calls `controller.swap_collateral(alice, account_id, USDC, amount, ETH, route)` (or `multiply`, `swap_debt`, `repay_debt_with_collateral`, or a direct `router.execute_strategy`). `swap_tokens` forwards the bytes to the router [1](#0-0) ; the router decodes and dispatches the hop to `RogueHopPool`.
4. Simulation records the rogue `transfer` as a child of Alice's `swap_collateral` auth entry; the swap still returns fair `ETH` output, so `verify_router_output` and all risk gates pass [13](#0-12) .
5. Alice signs the simulated tree; the host executes the rogue transfer, moving her entire wallet-token balance to the attacker, exactly as `enforced_auth_moves_the_wallet_token_only_when_the_signed_tree_lists_the_rogue_transfer` demonstrates [14](#0-13) .

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

**File:** contracts/swap-aggregator/src/lib.rs (L250-254)
```rust
    fn execute_strategy(env: Env, sender: Address, total_in: i128, swap_xdr: Bytes) -> i128 {
        renew_instance(&env);
        let payload = StrategyPayload::from_xdr(&env, &swap_xdr)
            .unwrap_or_else(|_| panic_with_error!(&env, Error::InvalidRouteXdr));
        execute::run(env, sender, total_in, payload)
```

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L195-227)
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

**File:** docs/reference/invariants.md (L665-672)
```markdown
### INV-STRAT-03 — Blend migration requires an approved pool

Blend migration requires the source Blend pool on the controller's
governance-managed approval list. Admission does not prove permanent integrity
of external code.

The router's separate token whitelist selects fee placement. It does not admit
tokens, venues or pools for migration.
```
