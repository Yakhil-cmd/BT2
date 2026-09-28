### Title
Caller-supplied route executes arbitrary contract code under the swapper's authorization tree, enabling wallet draining - (File: contracts/swap-aggregator/src/venues/mod.rs)

### Summary
The router dispatches each hop to a `pool` address taken verbatim from the caller-supplied XDR route, with no allowlist of venue contracts. A malicious "pool" invoked below `sender.require_auth()` can itself call `token.transfer(victim, attacker, x)`; in recording mode that call is attached as a sub-invocation of the victim's own auth entry, and if the victim signs the recorded tree it executes. This is the on-chain analog of CVE-2025-46334: attacker-planted code runs inside a trusted search/authorization scope simply because the caller invoked the operation.

### Finding Description
`dispatch_hop` in `contracts/swap-aggregator/src/venues/mod.rs:23-40` calls venue adapters with `hop.pool`, an address decoded from the `assets` registry inside the user-provided `swap_xdr`. There is no venue/pool allowlist (the router's whitelist only selects fee placement — `docs/reference/invariants.md` INV-STRAT-03). The venue adapters then `env.invoke_contract` into that attacker-controlled address while the sender's `require_auth()` from `execute_strategy` is still on the call stack.

Soroban auth semantics make this dangerous: any `require_auth` the rogue pool issues against the caller address is recorded as a child of the caller's existing authorization entry. The repository's own threat model documents this: "a route can put third-party code on the call stack below the caller's authorization… The loss is then the caller's wallet, not the routed amount" (`docs/explanation/threat-model.md:154-165`). The harness test `tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs` demonstrates it end-to-end: a `RogueHopPool.swap` performs `token.transfer(alice, attacker, WALLET_BALANCE)` for an unlisted token, and simulation records that transfer as a sub-invocation of Alice's `swap_collateral` entry (lines 195-227).

The same exposure exists for the controller-strategy path (`swap_collateral`, `swap_debt`, `repay_debt_with_collateral`, `multiply`) since `swap_tokens` in `contracts/controller/src/strategies/swap.rs` authorizes only one exact input transfer and passes the caller's route bytes through, and for direct `execute_strategy` calls on the router.

### Impact Explanation
Theft of user funds. A victim who submits a swap strategy built from an attacker-influenced route (phished quote, malicious frontend, crafted `routeXdr`) can have arbitrary token transfers recorded under their signature and executed — draining wallet balances unrelated to the swap, as shown by the harness test stealing `WALLET_BALANCE` of a token the protocol never listed. Losses are unbounded by the swap's `min_out` or the controller's risk gates.

### Likelihood Explanation
Exploitation requires the victim to sign a route containing the rogue pool and to accept the poisoned auth tree. The attacker is a fully unprivileged address — anyone can deploy a contract and embed its address in route bytes. Because instructions reference a flat `assets` registry by `u8` index and venues are keyed only by a 1-byte opcode, embedding an arbitrary pool address is trivial. The mitigation is entirely client-side (decode the signed auth tree and reject unexpected children), which the threat model itself states a client "must" do; nothing on-chain prevents the poisoned route. Users relying on a compromised or naive quoting path sign without ever seeing the route contents. Medium-high likelihood of occasional success, high impact per success.

### Recommendation
- Maintain an on-chain allowlist of venue pool/router addresses (governance-managed, like the Blend pool approval list used for `migrate_from_blend`) and reject hops whose `pool` is not registered.
- Alternatively, pin per-venue contract addresses or WASM hashes in router storage instead of trusting registry-supplied addresses.
- As defense-in-depth, document and enforce in the SDK/UI that any auth tree for `execute_strategy`/controller swap verbs containing sub-invocations beyond the single input `transfer` (or the controller's transfer) must be refused.

### Proof of Concept
`tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs`:
1. `RogueHopPool` (lines 54-72) is deployed with a `(victim, wallet_token, attacker, amount)` plan; its `swap` calls `token.transfer(victim, attacker, amount)`.
2. A `swap_collateral` route through `UnlistedPoolRouter` invokes the rogue pool via `env.invoke_contract(&route.hop_pool, "swap", …)` (line 44).
3. In recording mode (`simulation_records_the_rogue_pool_wallet_transfer_under_the_callers_swap_collateral_entry`, lines 195-227) the stolen transfer is recorded as a child of Alice's `swap_collateral` auth entry; asserting the recorded tree equals `[(alice, swap_collateral → [transfer(alice → attacker, WALLET_BALANCE)])]` and that Alice's wallet went from `77_770_000_000` to `0` while the swap still returned fair output proves the wallet drain succeeds whenever the poisoned tree is signed.