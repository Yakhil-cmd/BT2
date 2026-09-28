### Title
Arbitrary callee in a swap route can inject caller-signed token transfers - ([File: contracts/controller/src/strategies/swap.rs])

### Summary
A swap-strategy route can place attacker-controlled contract code beneath the caller’s `require_auth()` context. That code can request an unrelated `token.transfer(caller, attacker, amount)`, causing transaction simulation to add it as a child of the caller’s authorization; if the caller signs that tree, the unrelated wallet funds are transferred while the strategy still completes normally.

### Finding Description
`swap_collateral` authorizes the supplied `caller`, verifies account ownership or delegation, and invokes the configured swap router with caller-controlled route bytes. [1](#0-0) 

The controller authorizes only its own input-token transfer to the router, then measures the router’s input spend and output receipt. [2](#0-1)  Those checks bound only the strategy assets; they do not bound additional calls made by route-selected contracts under the caller’s authorization. [3](#0-2) 

The router authenticates `sender` and executes the payload-selected hop pool. [4](#0-3)  Each swap hop receives its pool and token addresses from the caller-supplied asset registry, and the venue dispatch does not require the pool to be allowlisted. [5](#0-4)  The repository’s host-level regression test demonstrates that a rogue hop can call `token.transfer(victim, attacker, amount)` and that simulation records it as a child authorization under `swap_collateral`. [6](#0-5) 

This is analogous to the PostgreSQL issue: the attacker does not break the authentication primitive itself; they inject an additional operation while an authenticated operation is being assembled. Here, TLS/certificate verification corresponds to Soroban authorization, while the injected SQL corresponds to an unrelated token transfer added to the caller’s signed authorization tree.

### Impact Explanation
An attacker can steal arbitrary token balances from a user who signs the poisoned authorization tree, including tokens unrelated to the lending position and not listed by the protocol. The strategy can still return a positive measured output and pass the controller’s solvency checks, so the wallet loss is not bounded by `amount_in`, route minimum output, or the position’s collateral. The regression test drains the victim’s full unrelated wallet-token balance while the requested collateral swap succeeds. [7](#0-6) 

### Likelihood Explanation
Likelihood is Medium. The attack requires the victim to submit or sign a route containing a malicious pool, but any unprivileged party can deploy such a pool and construct route bytes that reference it. An honest-looking route can still satisfy the configured minimum output, and a wallet or integration that trusts simulation without rejecting unexpected child authorization entries will sign the injected transfer. The test confirms the same route fails with an honest root-only authorization but succeeds once the injected child transfer is included in the signed tree. [8](#0-7) 

### Recommendation
Do not allow route bytes to name arbitrary executable pool contracts. Maintain a governance-controlled allowlist of venue/pool contract addresses for each supported venue, and reject any hop whose pool is not registered. At minimum, enforce this for every `Opcode::Swap` before dispatch. This prevents third-party code from executing beneath the caller’s authorization while preserving fixed venue adapters.

Wallets and integrations should additionally reject an authorization tree containing any unexpected child invocation. The protocol-level fix should not rely solely on client-side inspection.

### Proof of Concept
1. Victim owns a lending account and holds an unrelated wallet token.
2. Attacker deploys a pool-shaped contract whose swap entrypoint calls `token::transfer(victim, attacker, wallet_balance)`.
3. Attacker constructs otherwise valid route bytes whose hop pool is the malicious contract and whose returned output satisfies the route minimum.
4. Victim calls `Controller::swap_collateral(caller=victim, account_id, current, amount, new, route)`.
5. `swap_collateral` obtains the victim’s authorization, invokes the router, and the router invokes the attacker’s pool.
6. The pool requests `token.transfer(victim, attacker, wallet_balance)`. Simulation records it beneath the victim’s `swap_collateral` authorization.
7. If the victim signs the returned authorization tree, the unrelated tokens transfer to the attacker while the controller accepts the measured swap output and completes the collateral update. [9](#0-8)

### Citations

**File:** contracts/controller/src/strategies/swap_collateral.rs (L40-48)
```rust
    require_authorized_caller(env, caller);

    assert_with_error!(env, current != new, GenericError::AssetsAreTheSame);
    config::require_hub_active(env, current.hub_id);
    require_positive_amount(env, from_amount);

    let mut account = storage::get_account(env, account_id);
    account::require_owner_or_delegate(env, account_id, caller, &account.owner);
    let mut cache = Context::new(env);
```

**File:** contracts/controller/src/strategies/swap.rs (L29-38)
```rust
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

**File:** contracts/swap-aggregator/src/execute/mod.rs (L51-67)
```rust
pub(crate) fn run(env: Env, sender: Address, total_in: i128, payload: StrategyPayload) -> i128 {
    sender.require_auth();

    if total_in <= 0 {
        panic_with_error!(&env, Error::InvalidAmount);
    }

    let StrategyPayload {
        amounts,
        assets,
        ops,
    } = payload;
    let program = Program::decode(&env, &ops, assets.len(), amounts.len());

    let input_token = assets.get_unchecked(program.token_in);
    let output_token = assets.get_unchecked(program.token_out);
    let total_min_out = amounts.get_unchecked(program.min_out);
```

**File:** contracts/swap-aggregator/src/execute/mod.rs (L151-166)
```rust
    match op.opcode {
        Opcode::Swap(venue) => {
            let hop = SwapHop {
                pool: ctx.assets.get_unchecked(op.idx_a),
                token_in: ctx.assets.get_unchecked(op.idx_b),
                token_out: ctx.assets.get_unchecked(op.idx_c),
                venue,
            };
            let amount_in = resolve_amount(ctx, vault, op.mode, &hop.token_in, prev);
            if amount_in <= 0 {
                panic_with_error!(ctx.env, Error::InvalidAmount);
            }

            vault.withdraw(&hop.token_in, amount_in);
            let out = venues::dispatch_hop(ctx.env, ctx.router, &hop, amount_in, tokens_cache);
            if out <= 0 {
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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L229-268)
```rust
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
```
