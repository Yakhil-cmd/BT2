### Title
Unvalidated swap-route contracts can attach arbitrary token transfers to the caller’s authorization tree - ([File: contracts/controller/src/strategies/swap.rs](contracts/controller/src/strategies/swap.rs))

### Summary
`swap_collateral`, `swap_debt`, `repay_debt_with_collateral`, `multiply`, and `flash_position` paths can pass caller-controlled opaque swap payloads to the configured router. The controller authorizes only the expected `amount_in` transfer to that router, but the router may invoke arbitrary venue contracts embedded in the route. A malicious venue can execute additional token transfers from the caller; Soroban includes those transfers in the caller’s authorization tree rather than the router’s. If the caller signs the simulated tree without decoding its children, the transaction can transfer unrelated wallet assets to an attacker. This is analogous to DOM clobbering because a caller-controlled object substitutes untrusted code into a trusted execution path.

### Finding Description
`swap_tokens` loads the configured router and authorizes exactly one transfer of `token_in` from the controller to that router for `amount_in`. [1](#0-0) 

It then passes the opaque `swap` payload directly to `execute_strategy`; the controller does not inspect route venues or constrain which contracts the router invokes below the caller’s authorization. [2](#0-1) 

The subsequent checks only bound `token_in` spent from the controller and require a positive measured `token_out` delta. They do not detect unrelated token transfers made directly from the caller under a signed child authorization. [3](#0-2) 

The documented threat model confirms that route payload addresses are unallowlisted, that third-party route code executes below the caller’s authorization, and that a transfer from the caller becomes an authorized child invocation if the caller signs the generated tree. [4](#0-3) 

### Impact Explanation
An attacker can steal unrelated assets held by a user who submits an attacker-supplied route. The route can return enough `token_out` to satisfy measured-output and final risk checks while its malicious venue adds a child call transferring another token from the user to the attacker.

This is theft of user wallet funds, distinct from ordinary route quality or slippage loss. Neither the configured router’s expected input authorization nor the controller’s positive-output check bounds the added child transfer.

### Likelihood Explanation
Exploitation requires convincing a user to submit and sign a malicious route, including its expanded authorization tree. Wallets or clients that display only the top-level lending operation and exact input transfer may not clearly expose the additional child transfer. The attack is user-assisted and bounded to assets the victim authorizes in the poisoned tree, making it Medium rather than Critical or High.

### Recommendation
Constrain route execution to authenticated, allowlisted venue contracts or to venue descriptors that cannot invoke arbitrary contract addresses. At minimum, require route construction to carry an explicit expected authorization manifest and reject routes whose execution produces token-transfer children outside that manifest. Client integrations should also decode the complete Soroban authorization tree before signing and reject any child invocation unrelated to the exact advertised swap input.

### Proof of Concept
1. Deploy a malicious contract exposing the venue interface expected by the router.
2. Inside its swap callback, call `token.transfer(victim, attacker, victim_balance)` for an unrelated token held by the victim.
3. Construct an otherwise fair route through that contract, providing sufficient `token_out` for the controller’s measured-output check.
4. Have the victim submit `swap_collateral` with that route.
5. Transaction simulation reports the malicious token transfer as a child of the victim’s authorization; when the victim signs and submits it, the unrelated token moves to the attacker.
6. The repository’s authorization-tree regression test demonstrates the same behavior: after the poisoned tree is supplied, the malicious pool’s transfer succeeds and moves the victim’s full unrelated wallet balance to the attacker. [5](#0-4)

### Citations

**File:** contracts/controller/src/strategies/swap.rs (L24-35)
```rust
    let controller = env.current_contract_address();
    let router_addr = storage::get_swap_aggregator(env);
    let router = SwapAggregatorClient::new(env, &router_addr);
    let token_in_client = token::Client::new(env, token_in);

    // Snapshot before router execution to measure its spend and output.
    let in_before = token_in_client.balance(&controller);
    let out_before = token::Client::new(env, token_out).balance(&controller);

    // Authorize only this token transfer to this router for this exact amount.
    authorize_transfer_as_current(env, token_in, &controller, &router_addr, amount_in);

```

**File:** contracts/controller/src/strategies/swap.rs (L36-38)
```rust
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
