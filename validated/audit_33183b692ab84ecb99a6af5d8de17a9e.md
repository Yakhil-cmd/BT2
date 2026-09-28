### Title
Malicious swap route can attach arbitrary wallet token transfers to the caller's authorization tree - ([File: contracts/controller/src/strategies/swap.rs])

### Summary
Controller strategy swaps invoke a caller-supplied route through the configured swap aggregator. The controller constrains its own input transfer, but it does not constrain which venue contracts the route invokes. A malicious venue can therefore call `token.transfer(victim, attacker, amount)` while the victim's authorization is active; Soroban records that nested transfer under the victim's signed authorization tree. If the victim signs the simulation-produced tree without noticing the added transfer, the attacker steals unrelated wallet assets even though the protocol swap itself remains solvent.

### Finding Description
`swap_collateral` authorizes the caller and verifies account ownership before invoking the route execution path. [1](#0-0)  The generic swap helper then invokes `execute_strategy` with caller-controlled `swap` bytes and measures only the controller's input/output token balances. [2](#0-1) 

Those measurements detect router overspending and missing output, but they do not constrain calls that route-selected code makes to unrelated token contracts using the original caller's authorization. [3](#0-2)  The regression test demonstrates that a route-selected contract can execute `token.transfer(victim, attacker, amount)`, that simulation records it under the victim's `swap_collateral` authorization, and that signing that tree moves the victim's wallet token to the attacker. [4](#0-3) 

This is analogous to the reported wallet compromise: the attacker obtains an asset transfer outside the funds deliberately committed to the operation. No private key or privileged protocol role is required; the attacker supplies a crafted route and gets the victim to authorize the poisoned transaction tree.

### Impact Explanation
The attacker can steal arbitrary balances held in the victim's wallet, including tokens unrelated to the lending account. The demonstrated transfer drains the victim's entire 77,770-unit wallet-token balance to the attacker while the strategy still deposits the expected swap output. [5](#0-4) 

This qualifies as theft of user funds. The loss is bounded by assets spendable through the victim's signed authorization tree, not by the swap input or the account's collateral.

### Likelihood Explanation
The attack requires the victim to submit a malicious route and sign the simulation-generated authorization tree containing the extra token transfer. The account-owner check does not prevent it because the malicious operation executes while the legitimate owner is already authorized. [6](#0-5) 

The enforced-auth control shows that an unsigned rogue transfer is rejected, confirming that signing the poisoned tree is the enabling condition rather than a separate contract compromise. [7](#0-6) 

### Recommendation
Constrain route execution so user-controlled venue addresses cannot place arbitrary sub-invocations under the caller's authorization. Prefer an allowlisted venue dispatch in which every invoked contract address and function is protocol-controlled, or execute routes through an isolated authorization context that cannot reuse the user's root authorization for unrelated token transfers.

At minimum, clients must decode simulation results and reject any authorization tree beneath a strategy call other than the expected protocol input transfer. [8](#0-7) 

### Proof of Concept
1. The victim supplies USDC collateral and holds an unrelated token in the same wallet.
2. The attacker deploys a malicious route component whose `swap` function calls `token.transfer(victim, attacker, victim_balance)`.
3. The victim invokes `swap_collateral(caller=victim, account_id, current=USDC_market, amount, new=ETH_market, swap=malicious_route)`.
4. `swap_collateral` passes ownership checks and calls `swap_tokens`; `swap_tokens` invokes the configured router with the attacker-controlled route bytes. [9](#0-8) 
5. During simulation, the malicious token transfer is recorded as a child of the victim's controller authorization. [10](#0-9) 
6. The victim signs that authorization tree. The malicious transfer then succeeds, draining the unrelated wallet token to the attacker while the collateral swap completes. [5](#0-4)

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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L239-250)
```rust
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
