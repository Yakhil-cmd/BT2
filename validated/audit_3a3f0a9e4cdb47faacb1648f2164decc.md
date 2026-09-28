### Title
Caller-supplied swap route can abuse the caller's authorization to steal unrelated wallet tokens - (File: contracts/controller/src/strategies/swap.rs)

### Summary
Severity: High.

The lending strategy verbs accept opaque `swap` bytes and execute them through the configured router while the account owner's authorization is active for the entire controller invocation. Because the route can name arbitrary token and venue/pool addresses, a malicious venue can execute contract code underneath that authorization and invoke `token.transfer(victim, attacker, amount)` on an unrelated token held by the victim. Transaction simulation records that transfer as a child of the victim's authorization; if the victim signs the simulated authorization tree, the token transfer executes even though the lending strategy itself only intended to authorize the routed input token.

### Finding Description
`swap_collateral` requires the caller to be the account owner or an active delegate, then executes the caller-controlled `swap` payload while processing the strategy. [1](#0-0) 

The controller's generic swap path forwards the unvalidated `StrategySwap` to the configured router and authorizes one exact input transfer from the controller to the router. [2](#0-1) 

That authorization only protects the controller's routed input. It does not prevent arbitrary contract code reached through the route from attempting another operation that requires the original account caller's authorization. The router accepts route-selected hop pool/token addresses and dispatches each hop to venue code without a protocol-level allowlist. [3](#0-2) 

A malicious pool can therefore call a token contract with `transfer(victim, attacker, amount)`. During transaction simulation, Soroban records that nested call under the victim's authorization for `swap_collateral`, `swap_debt`, `repay_debt_with_collateral`, or `multiply`. Signing the resulting tree authorizes both the intended lending operation and the unrelated wallet transfer.

The repository's threat-model documentation explicitly describes this boundary: route-selected code can make a caller-token transfer appear as a child of the caller's authorization, and neither the route minimum nor final account-risk checks bound that wallet loss. [4](#0-3) 

### Impact Explanation
A victim can lose arbitrary balances of unrelated Stellar Asset Contract tokens from their wallet, not merely the collateral or debt amount supplied to the lending strategy. The malicious route can still return enough output for the strategy's measured-output and health-factor checks to pass, so the transaction appears successful while the unrelated transfer is executed in the same authorization tree. [5](#0-4) 

This is theft of user funds. The stolen amount is bounded by the victim's wallet balances and the malicious transfers included in the signed authorization tree, rather than by the strategy amount.

### Likelihood Explanation
Exploitation requires the victim to submit a malicious route and sign the poisoned authorization tree produced by simulation. That is plausible where opaque `routeXdr` bytes are supplied by a frontend, quote service, bot, or another integrating contract, because the signed tree—not the human-readable route—contains the additional token transfer. [6](#0-5) 

An attacker cannot directly invoke these strategy verbs against another user's account because the controller checks owner/delegate authority. [7](#0-6) 

The practical attack vector is therefore malicious routing or a compromised integration that causes the victim to sign an authorization tree containing an unexpected child token transfer.

### Recommendation
Constrain swap execution so route-selected code cannot perform unrelated authorization-bearing calls:

1. Enforce an allowlist of known pool/venue contract addresses for production routes, or require venue-specific adapters to validate pools from a governance-approved registry.
2. Decode and validate every hop's `pool`, `token_in`, and `token_out` before invoking the router.
3. Reject routes whose simulation produces any caller-authorization child invocation other than the expected exact input transfer.
4. Surface decoded authorization trees in client integrations and fail closed if a swap strategy contains extra `token.transfer`, `token.approve`, NFT, or other unrelated child calls.
5. Prefer a route format whose executable addresses are fixed by protocol configuration rather than supplied entirely by the caller.

### Proof of Concept
1. Alice owns a lending account with USDC collateral and also holds a large balance of an unrelated token `WALLET_TOKEN`.
2. The attacker deploys a malicious contract implementing the pool interface expected by a supported venue adapter.
3. The malicious contract's swap entrypoint calls:

   `WALLET_TOKEN.transfer(alice, attacker, alice_balance)`

   and otherwise performs or simulates enough output for the route to satisfy the router's minimum-output accounting.
4. The attacker constructs route bytes whose hop pool address is the malicious contract and whose declared `token_in`/`token_out` still match the expected USDC-to-collateral swap.
5. Alice submits, or is induced by a malicious integration to submit, `swap_collateral(caller=alice, account_id, current=USDC, amount, new=ETH, swap=route)`.
6. Simulation records the malicious `WALLET_TOKEN.transfer` as a child invocation beneath Alice's `swap_collateral` authorization.
7. Alice signs the simulated authorization tree. The strategy swaps the intended collateral successfully, and the same transaction transfers Alice's unrelated `WALLET_TOKEN` balance to the attacker.

The controller's post-swap checks only bound the controller-held routed input and measured output; they do not inspect or bound unrelated token movements authorized by Alice's signed tree. [5](#0-4)

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

**File:** contracts/swap-aggregator/src/execute/mod.rs (L152-165)
```rust
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
