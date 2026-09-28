### Title
Unvalidated swap routes can inject third-party code under the caller’s authorization - (File: contracts/controller/src/strategies/swap.rs)

### Summary
`swap_collateral`, `swap_debt`, `repay_debt_with_collateral`, and `multiply` accept an opaque route payload and forward it to the configured swap router. The controller constrains only its own input transfer and measured output, but does not constrain contracts invoked by the route. A malicious route can therefore place attacker-controlled code inside the transaction’s authorization tree and request transfers of unrelated caller-held tokens. [1](#0-0) 

### Finding Description
`swap_tokens` forwards the caller-supplied `StrategySwap` payload to `SwapAggregatorClient::execute_strategy`. Before doing so, the controller authorizes only an exact `token_in.transfer(controller, router, amount_in)` invocation. [2](#0-1) 

That grant protects the controller’s routed input, but it does not bound what route-selected contracts may request from the original caller. On Soroban, a nested contract can invoke a token `transfer` that requires the caller’s authorization; simulation records that transfer as a child of the caller’s authorization entry. If the caller signs the resulting tree, the transfer executes. The project threat model explicitly notes that route-selected pool and token addresses are not allowlisted and that such a transfer can drain the caller’s wallet rather than merely the routed amount. [3](#0-2) 

The public `swap_collateral` entrypoint accepts the attacker-controlled `swap: Bytes` argument and reaches `withdraw_and_swap_from_supply`, which in turn reaches `swap_tokens`. [4](#0-3) [5](#0-4) 

### Impact Explanation
A victim who executes a malicious route can lose wallet tokens unrelated to the lending position, in addition to the collateral intentionally routed through the swap. The controller’s positive-output and final-risk checks do not prevent this loss because the stolen asset need not be part of the swap’s measured `token_in` or `token_out` balances. [6](#0-5) 

The project’s harness demonstrates the concrete result: a route-selected contract requests `wallet_token.transfer(victim, attacker, WALLET_BALANCE)`, simulation attaches that transfer beneath `swap_collateral`, and the signed tree moves the victim’s entire unrelated wallet balance to the attacker while the swap itself still returns fair output. [7](#0-6) 

### Likelihood Explanation
Exploitation requires the victim to execute and authorize a malicious route, including the additional token-transfer authorization produced by simulation. This is a meaningful prerequisite, but normal quote/signature flows can obscure opaque route bytes and nested authorization entries from users. The test demonstrates both halves of the authorization behavior: the honest tree rejects the rogue transfer, while the simulated poisoned tree authorizes it. [8](#0-7) 

The affected entrypoints are permissionless account-owner paths rather than administrative operations. `swap_collateral` is the simplest path; `swap_debt`, `repay_debt_with_collateral`, and `multiply` expose the same opaque route boundary. [9](#0-8) [10](#0-9) [11](#0-10) 

### Recommendation
Do not treat a signed controller invocation as proof that every nested caller authorization is intended. Prefer router support for an allowlisted set of venue contracts and token contracts, or a bounded route format that prevents arbitrary callee addresses. At minimum, enforce client-side validation that rejects any authorization tree containing children beyond the expected input transfer, and surface route-selected contract addresses before signing. The current threat-model guidance relies on clients performing that check. [12](#0-11) 

### Proof of Concept
1. The victim supplies USDC and owns an unrelated wallet token not listed by the lending protocol.
2. The attacker deploys a fake hop contract whose swap function calls `wallet_token.transfer(victim, attacker, wallet_balance)`.
3. The attacker provides a `swap_collateral` route that pays fair `token_out`, so the controller’s measured output and final account checks pass.
4. During simulation, the fake hop’s `transfer` is attached as a child of the victim’s `swap_collateral` authorization.
5. If the victim signs that returned tree, the transaction performs the collateral swap and also transfers the unrelated wallet token to the attacker.

The harness implements the malicious hop at `tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs:50-70`, records the poisoned authorization at lines 195-226, and confirms that the signed poisoned tree drains the wallet at lines 258-268.

### Citations

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

**File:** contracts/controller/src/lib.rs (L280-301)
```rust
    /// Withdraws `amount` of `current`, converts it to `new` via `swap` and
    /// redeposits the proceeds. Requires owner or delegate authorization.
    #[when_not_paused]
    fn swap_collateral(
        env: Env,
        caller: Address,
        account_id: u64,
        current: HubAssetKey,
        amount: i128,
        new: HubAssetKey,
        swap: Bytes,
    ) {
        strategies::swap_collateral::process_swap_collateral(
            &env,
            &caller,
            SwapCollateralParams {
                account_id,
                current: &current,
                from_amount: amount,
                new: &new,
                swap: &swap,
            },
```

**File:** contracts/controller/src/strategies/legs.rs (L231-258)
```rust
/// Withdraws to the controller, then swaps its measured receipt into `token_out`.
/// Matching assets pass through unchanged; returns the available output.
pub(crate) fn withdraw_and_swap_from_supply(
    env: &Env,
    account: &mut Account,
    cache: &mut Context,
    caller: &Address,
    from: &HubAssetKey,
    amount: i128,
    token_out: &Address,
    swap: &StrategySwap,
    action: events::PositionAction,
) -> i128 {
    let supply_pos = get_supply_position_or_panic(env, account, from);

    let actual_withdrawn = withdraw_collateral_to_controller(
        env,
        account,
        cache,
        StrategyWithdraw {
            hub_asset: from,
            amount,
            position: &supply_pos,
            action,
        },
    );

    swap_tokens_or_passthrough(env, caller, &from.asset, actual_withdrawn, token_out, swap)
```

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L195-226)
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

**File:** contracts/controller/src/strategies/swap_collateral.rs (L27-47)
```rust
pub(crate) fn process_swap_collateral(
    env: &Env,
    caller: &Address,
    params: SwapCollateralParams<'_>,
) {
    let SwapCollateralParams {
        account_id,
        current,
        from_amount,
        new,
        swap,
    } = params;

    require_authorized_caller(env, caller);

    assert_with_error!(env, current != new, GenericError::AssetsAreTheSame);
    config::require_hub_active(env, current.hub_id);
    require_positive_amount(env, from_amount);

    let mut account = storage::get_account(env, account_id);
    account::require_owner_or_delegate(env, account_id, caller, &account.owner);
```

**File:** contracts/controller/src/strategies/swap_debt.rs (L55-72)
```rust
    let amount_received = borrow_into_controller(
        env,
        &mut account,
        new_debt,
        new_debt_amount,
        true,
        PositionAction::SwDebtR,
        &mut cache,
    );

    let repay_amount = swap_tokens_or_passthrough(
        env,
        caller,
        &new_debt.asset,
        amount_received,
        &existing_debt.asset,
        swap,
    );
```

**File:** contracts/controller/src/strategies/multiply.rs (L187-194)
```rust
        let collateral_amount = swap_tokens(
            env,
            caller,
            &payment.asset,
            received,
            &collateral.asset,
            convert,
        );
```
