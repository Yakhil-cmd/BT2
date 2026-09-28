### Title
Unallowlisted route venues let a payload-named contract execute arbitrary calls under the caller's signed auth tree and drain their wallet - (File: contracts/swap-aggregator/src/venues/mod.rs)

### Summary
CVE-2024-7553 is an "untrusted content is loaded and executed" bug class: MongoDB loaded files from an attacker-controlled directory and ran whatever behavior they defined. The on-chain analog lives in the XOXNO swap router: `execute_strategy` decodes a caller-supplied `StrategyPayload` whose `assets` registry names the pool/token contracts each hop invokes, keeps no allowlist of them, and runs those contracts on the same call stack where the sender's `require_auth` authorization is active. A route can therefore name an attacker-deployed "pool" that executes a `token.transfer(victim, attacker, amount)` for any token; in simulation that call is recorded as a child of the caller's own authorization entry, and it executes if the caller signs the simulated tree. The loss is the victim's whole wallet balance of that token, bounded by neither the payload `min_out` nor the controller's final risk gates.

### Finding Description
The router executes hops against venue addresses taken verbatim from the untrusted payload. `dispatch_hop` invokes `hop.pool` (resolved from `assets[idx_a]`) with no allowlist check, and every venue adapter then performs a contract call into that address — e.g. `env.invoke_contract(&ctx.hop.pool, "swap_exact_amount_in", ...)` for Comet [1](#0-0)  and the dispatcher match in `contracts/swap-aggregator/src/venues/mod.rs` [2](#0-1) . The threat model confirms "the router calls the pool and token addresses its payload names and keeps no allowlist of them, so a route can put third-party code on the call stack below the caller's authorization" [3](#0-2) .

Because the sender's only signature is the root `execute_strategy` (or a controller verb like `swap_collateral`) entry, any `require_auth` a rogue hop contract triggers on the sender is recorded under that root during simulation. The harness test `rogue_hop_pool_transfer_joins_caller_auth_tree.rs` proves end-to-end that a payload-named `RogueHopPool.swap` calling `token.transfer(alice, attacker, WALLET_BALANCE)` is recorded as a sub-invocation of Alice's `swap_collateral` entry and drains her full balance of an unrelated, never-listed token [4](#0-3) [5](#0-4) .

The controller's own protections do not bound this: `swap_tokens` in `contracts/controller/src/strategies/swap.rs` authorizes only the exact input transfer and measures balance deltas, but both checks pass while the rogue hop steals unrelated tokens via the auth tree [6](#0-5) .

### Impact Explanation
Theft of user funds. Any token the victim holds — including assets the protocol never listed — can be transferred to the attacker in the same transaction as a legitimate-looking swap. The amount is unbounded by `total_in`, `min_out`, or post-swap account health; the test drains 77,770,000,000 units while the swap itself settles a "fair" output [7](#0-6) . Reachable through `execute_strategy` directly and through the controller verbs `swap_collateral`, `swap_debt`, `multiply`, and `repay_debt_with_collateral` in `contracts/controller/src/strategies/swap.rs`.

### Likelihood Explanation
Exploitation requires the victim to sign a poisoned route: the stolen `transfer` appears as a child node in the simulated authorization tree, so a wallet or client that inspects the tree can refuse it. The threat model places verification duty on the client [8](#0-7) , but nothing on-chain enforces it — any tooling that serves or relays `routeXdr` without decoding (or that displays only the root entry, as many wallets do for nested Soroban auth) exposes its users. A single unprivileged attacker only needs to register a malicious contract and craft a payload; the contract-side root cause (unallowlisted payload-named contract invocation below caller auth) is fully present in the code. Rated High: critical impact, conditioned on the victim signing a tree produced by an untrusted route source.

### Recommendation
Do not invoke venue addresses supplied only by the payload. Maintain an on-chain allowlist (or signed venue registry) of acceptable pool contracts per venue in the swap-aggregator, or pin each hop's pool to a value the venue adapter can authenticate (e.g., derived from a factory or the router's storage). Short of that, restrict the sender-visible auth footprint: have the controller/router perform hops so that any `require_auth` a venue triggers resolves against contract invoker auth only, and document/enforce that a `transfer` on the sender inside a hop must be impossible — e.g., reject routes whose hop address is not the expected pool for the declared venue. Clients must additionally decode `routeXdr` and reject any authorization tree whose root carries children other than the single input transfer.

### Proof of Concept
The repository already contains the working exploit as a pinned regression scenario, `tests/test-harness/tests/controller/rogue_hop_pool_transfer_joins_caller_auth_tree.rs`:

1. Attacker deploys `RogueHopPool` whose `swap()` reads a stored plan `(victim, wallet_token, attacker, amount)` and calls `token::Client::new(&wallet_token).transfer(&victim, &attacker, &amount)` [4](#0-3) .
2. A route payload names that contract as `hop_pool` while `token_in`/`token_out` are legitimate USDC/ETH markets [9](#0-8) .
3. The victim calls `swap_collateral` (or `execute_strategy` directly). Simulation records the rogue pool's `transfer` as a child of the victim's own authorization entry [10](#0-9) .
4. With the recorded tree signed, the swap settles fairly (`supply_balance_raw(ALICE, "ETH") == FAIR_OUT_ETH`) while `wallet(alice) == 0` and `wallet(attacker) == WALLET_BALANCE` [11](#0-10) .

The analogous production flow is identical: `dispatch_hop` reaches an attacker-named `hop.pool` via `assets[idx_a]` [2](#0-1) , and the victim-facing entrypoints are `SwapAggregatorClient::execute_strategy` [12](#0-11)  and the controller strategy verbs routed through `swap_tokens` [13](#0-12) .

### Citations

**File:** contracts/swap-aggregator/src/venues/comet.rs (L30-34)
```rust
    let _: (i128, i128) = ctx.env.invoke_contract(
        &ctx.hop.pool,
        &Symbol::new(ctx.env, "swap_exact_amount_in"),
        args,
    );
```

**File:** contracts/swap-aggregator/src/venues/mod.rs (L34-40)
```rust
    match hop.venue {
        SwapVenue::Soroswap => soroswap::swap(&ctx),
        SwapVenue::Aquarius => aquarius::swap(&ctx, tokens_cache),
        SwapVenue::Phoenix => phoenix::swap(&ctx),
        SwapVenue::Sushi => sushi::swap(&ctx),
        SwapVenue::CometDex => comet::swap(&ctx),
    };
```

**File:** docs/explanation/threat-model.md (L154-159)
```markdown
That bound covers the controller's own grant only. The router calls the pool
and token addresses its payload names and keeps no allowlist of them, so a
route can put third-party code on the call stack below the caller's
authorization. A token transfer that such code makes from the caller is
recorded by an honest simulation as a child of the caller's authorization
entry, and it executes if the caller signs that tree. The loss is then the
```

**File:** docs/explanation/threat-model.md (L160-165)
```markdown
caller's wallet, not the routed amount, and neither the payload minimum nor the
final risk gate bounds it. An honest swap strategy gives the caller no child
entry, and a direct router swap gives exactly one input transfer. A client must
decode the route it signs and refuse an authorization tree with any other
child. The direct `execute_strategy` path has the same exposure for every swap
user.
```

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

**File:** interfaces/swap-aggregator/src/lib.rs (L20-20)
```rust
    fn execute_strategy(env: Env, sender: Address, total_in: i128, swap_xdr: Bytes) -> i128;
```
