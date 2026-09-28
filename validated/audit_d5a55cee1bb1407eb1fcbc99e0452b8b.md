### Title
Crafted swap route executes attacker-chosen contract code inside the victim's authorization tree, draining wallet tokens - (File: contracts/controller/src/strategies/swap.rs)

### Summary
The advisory class is "a crafted payload fed into a processing pipeline causes execution of attacker-controlled code." The analog is the controller's strategy verbs (`swap_debt`, `swap_collateral`, `repay_debt_with_collateral`, `multiply`, `flash_position`) accepting caller-supplied `swap` route bytes that the swap aggregator executes as a program, invoking pool addresses named by the payload with `env.invoke_contract` and no allowlist. A malicious "pool" in the route can call `token.transfer(victim, attacker, …)`, which the host records as a child of the victim's signed auth entry — theft of the victim's wallet funds, not just the routed amount.

### Finding Description
`swap_tokens` in `contracts/controller/src/strategies/swap.rs` forwards the raw `StrategySwap` bytes to the configured router via `router.execute_strategy(&controller, &amount_in, swap)` after granting only one exact input-transfer authorization (lines 34–37). It validates only balance deltas afterward (`RouterOverspend`, `NoSwapOutput`, lines 42–54, 75–84) — it never inspects which contracts the route invokes. [1](#0-0) 

On the router side, each hop calls `env.invoke_contract(&ctx.hop.pool, …)` where `pool` comes from the decoded payload; `docs/explanation/threat-model.md` confirms "the router calls the pool and token addresses its payload names and keeps no allowlist of them" (lines 154–156). [2](#0-1) 

When a Soroban token's `transfer` runs under that rogue pool frame with `victim.require_auth()`, the host joins the invocation to the nearest authorized ancestor — the victim's `swap_collateral` (or `swap_debt`/`multiply`) auth entry. If the victim signs the auth tree produced by `simulateTransaction` without decoding it, the rogue pool can move any token the victim holds, in any amount, unrelated to the routed funds.

The harness pins exactly this: `UnlistedPoolRouter` calls the payload-named `hop_pool`, and `RogueHopPool::swap` performs `token::Client::transfer(victim, attacker, WALLET_BALANCE)`. The test `simulation_records_the_rogue_pool_wallet_transfer_under_the_callers_swap_collateral_entry` shows simulation records the stolen transfer as a child of Alice's `swap_collateral` root and `enforced_auth_moves_the_wallet_token_only_when_the_signed_tree_lists_the_rogue_transfer` shows it executes once the poisoned tree is signed (Alice's wallet balance goes to 0). [3](#0-2) 

### Impact Explanation
Theft of user funds. The loss is the victim's entire wallet balance of any token the rogue transfer names — unbounded by the routed amount, the payload `min_out`, or the controller's final health-factor check. The swap can even deliver a fair output so the victim's position looks correct while a separate wallet token is drained.

### Likelihood Explanation
Any unprivileged address can craft a route (off-chain `routeXdr` or direct) naming an attacker-deployed pool and get a victim to submit a strategy verb with it — e.g., via a malicious quote/frontend — since the route bytes are opaque to most signers. Exploitation requires the victim to sign an auth tree containing the unexpected child transfer; the standard flow of "simulate → sign returned auth" produces exactly that poisoned tree, and the threat model itself notes the protocol relies on the client to decode and refuse it. Mitigations exist only off-chain (client-side tree inspection), which lowers likelihood but does not eliminate the on-chain exposure.

### Recommendation
Keep a venue/pool allowlist (or verify pool addresses against known registries) in the router's hop dispatch so a route cannot name arbitrary contracts, or have the controller constrain routes to known pools. At minimum, enforce on-chain that no `require_auth` on the `sender`/`caller` address may be satisfied below the swap frames — e.g., by checking invocation structure or documenting and surfacing a canonical expected auth-tree shape so wallets can diff it before signing.

### Proof of Concept
Replicated by `tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs`:

1. Attacker deploys `RogueHopPool` initialized with `(victim, wallet_token, attacker, amount)`; its `swap()` calls `wallet_token.transfer(victim, attacker, amount)` — which triggers `victim.require_auth()` inside the call tree.
2. Victim calls `controller.swap_collateral(alice, account_id, USDC_key, swap_in, ETH_key, route)` where `route` names the rogue pool.
3. `swap_tokens` authorizes only the exact input transfer and calls `router.execute_strategy`; the router `invoke_contract`s the rogue pool (`UnlistedPoolRouter` at lines 39–47 demonstrates the dispatch).
4. The rogue `transfer` is recorded by simulation as a sub-invocation of Alice's `swap_collateral` auth entry; once Alice signs that tree, the host authorizes it and her `WALLET_BALANCE` moves to the attacker — asserted at lines 224–226 and 265–269. The honest unsigned-child case correctly reverts (lines 244–256), confirming the only barrier is the victim signing the tree simulation produced.

### Citations

**File:** contracts/controller/src/strategies/swap.rs (L33-48)
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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L50-72)
```rust
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
}
```
