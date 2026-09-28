### Title
Crafted swap route attaches arbitrary `token.transfer` calls to the caller's authorization tree, draining wallet funds beyond the routed amount - (File: contracts/controller/src/strategies/swap.rs)

### Summary
Analogous to CVE-2025-12431 — where a user-installed malicious extension bypasses Chrome's navigation restrictions — a user-submitted `StrategySwap` payload can name arbitrary on-chain code as a route venue, and that code can attach extra `token.transfer` sub-invocations beneath the caller's own `require_auth` tree. The controller's "one exact input transfer" grant (`authorize_transfer_as_current`) scopes only what the *controller* authorizes; it does not bound what the *caller's* auth entry covers. A crafted route therefore bypasses the intended restriction that a strategy call may only move `amount_in` of `token_in`, and can transfer any token the caller holds to an attacker.

### Finding Description
Every routed account strategy (`multiply`, `swap_collateral`, `swap_debt`, `repay_debt_with_collateral`) forwards attacker/quote-supplied `swap` bytes to the configured router inside `swap_tokens`:

```rust
// contracts/controller/src/strategies/swap.rs
authorize_transfer_as_current(env, token_in, &controller, &router_addr, amount_in);
storage::with_flash_guard(env, || {
    let _ = router.execute_strategy(&controller, &amount_in, swap);
});
```

`authorize_transfer_as_current` narrows only the controller's own invocation authority (INV-STRAT-01: one exact `token_in.transfer(controller, router, amount_in)`, no allowance). But the router executes hop venues named in the payload with no venue allowlist, and any `token.transfer(victim, attacker, x)` issued inside a hop runs under the *user's* root `require_auth` (e.g., `require_authorized_caller` / `require_owner_or_delegate` in `swap_collateral`). In simulation (recording mode) the rogue transfer is recorded as a child of the user's `swap_collateral` authorization entry; if the user signs the recorded tree, the host executes it in enforcing mode.

The harness proves this end-to-end in `tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs`: `RogueHopPool::swap` calls `wallet_token.transfer(alice, attacker, WALLET_BALANCE)` inside a `swap_collateral` route, the simulation records it under Alice's auth entry (`simulation_records_the_rogue_pool_wallet_transfer_under_the_callers_swap_collateral_entry`), and signing that tree transfers her full unlisted-token balance to the attacker while the swap itself settles fairly (`enforced_auth_moves_the_wallet_token_only_when_the_signed_tree_lists_the_rogue_transfer`). The same exposure exists for the direct `execute_strategy` path and for every routed controller verb.

### Impact Explanation
Theft of user funds. The loss is the caller's whole wallet, not the routed amount: the route's `min_out` and the controller's `verify_router_output`/`strategy_finalize` gates can all pass because the swap output is honest — the theft is a side-band transfer authorized by the user's own signature. Neither `RouterOverspend` (input-balance check), `NoSwapOutput`, nor the final HF/LTV gates bound it, exactly mirroring the CVE's "bypass navigation restrictions via a crafted extension": the restriction (one input transfer) is bypassed by a crafted, user-invoked payload.

### Likelihood Explanation
Requires the attacker to convince a user to sign a poisoned route (e.g., a malicious quote service, phishing UI, or fake extension serving crafted `routeXdr`) — the same trust exploitation shape as the Chrome bug. Execution itself is a single unprivileged call (`swap_collateral`/`multiply`/etc.) with no privileged access needed. The protocol's own docs acknowledge the gap ("A client must decode the route it signs and refuse an authorization tree with any other child"), confirming the contract provides no defense in depth.

### Recommendation
- Constrain router authority and route structure on-chain: enforce a venue/pool allowlist (governance-managed) so payloads cannot name arbitrary contracts.
- Where feasible, execute routes in a context that cannot attach sub-invocations to the caller's auth entry — e.g., have the router `require_auth` only its own address and pull input via the controller's grant, and document/verify at the SDK layer that an honest strategy produces an auth tree with exactly one input-transfer child.
- Surface a simulation-time check in the quoting/signing path rejecting any authorization tree with unexpected sub-invocations.

### Proof of Concept
`tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs` demonstrates the full flow: attacker deploys `RogueHopPool` with a plan `(alice, wallet_token, attacker, WALLET_BALANCE)`; the route XDR names that pool; Alice calls `swap_collateral`; simulation records `wallet_token.transfer(alice → attacker, WALLET_BALANCE)` under her auth entry; signing that tree drains `WALLET_BALANCE` while the swap pays fair output. In production the same pattern works through the real swap-aggregator, which keeps no allowlist of payload-named pools.