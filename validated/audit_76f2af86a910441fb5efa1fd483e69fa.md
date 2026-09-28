### Title
Unallowlisted hop-pool addresses in swap routes let a rogue venue graft a caller-authorized `transfer` and drain wallet tokens beyond the routed input — (File: contracts/controller/src/strategies/swap.rs; pinned by tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs)

### Summary
Analog to CVE-2021-30638 (crafted path reaching protected resources due to incomplete validation): a swap route is a caller-supplied path of contract addresses. The swap-aggregator keeps no allowlist of pool/token addresses a payload names, so an attacker-crafted route can put arbitrary contract code on the call stack *underneath* the user's `require_auth` tree. That code can invoke `token.transfer(victim, attacker, amount)`; because the victim's `swap_collateral` / `execute_strategy` auth entry covers all nested invocations, a wallet-draining transfer is recorded by simulation as a child of the caller's own authorization and executes once the caller signs the simulated tree. Nothing in the controller's measured input/output accounting bounds this — the loss is the caller's whole wallet balance, not the routed amount.

### Finding Description
- `execute_strategy` pulls exactly `token_in` from the sender via measured transfer, then dispatches hops to whatever `pool`/`token` addresses the packed program names; `venues` adapters call `env.invoke_contract(&ctx.hop.pool, ...)` with no allowlist (`contracts/swap-aggregator/src/venues/comet.rs`, `program.rs`).
- The controller wraps this identically: `strategies/swap.rs` runs `authorize_transfer_as_current(token_in, self, router, amount_in)` and only verifies balance deltas (`RouterOverspend`, `NoSwapOutput`) plus final account risk. There is no independent bound on what route-named contracts do while on the stack.
- The repo's own threat model states the exposure verbatim: "a route can put third-party code on the call stack below the caller's authorization... The loss is then the caller's wallet, not the routed amount" (`docs/explanation/threat-model.md:154-165`). The mitigation is delegated to off-chain clients ("a client must decode the route it signs"), leaving the on-chain path open.
- The harness test `rogue_hop_pool_transfer_joins_caller_auth_tree.rs` proves end-to-end exploitability: a route naming a `RogueHopPool` contract that calls `token.transfer(alice → attacker, WALLET_BALANCE)` is accepted in recording mode; the stolen transfer is recorded as a child of Alice's `swap_collateral` auth entry; signing the simulated tree moves her entire wallet token balance to the attacker (test lines 194-269).

### Impact Explanation
Theft of user funds. Any token the victim holds (not just the swap input) can be transferred out in the same transaction once they sign the poisoned auth tree — exactly the "crafted path reaches a protected resource" shape: the route is the URL, the wallet token is the WEB-INF file, and the missing venue allowlist is the incomplete normalization.

### Likelihood Explanation
Requires a malicious route reaching the user (compromised/malicious quote source or attacker-suggested route) and the user signing a simulation-derived auth tree without diffing children. Both are plausible for the reachable entrypoints `swap_collateral`, `swap_debt`, `repay_debt_with_collateral`, `multiply` (via strategies), and direct `execute_strategy` calls. The codebase confirms feasibility but treats it as a documented client-side responsibility, which weakens but does not eliminate the finding — on-chain, the authorization boundary is violated.

### Recommendation
On-chain allowlist of callable pool/venue contracts (or venue adapter→pool registry) in the swap-aggregator so a payload can only name vetted addresses; alternatively restrict hop calls to the `assets` registry entries the router itself controls. Do not rely solely on off-chain clients refusing poisoned auth trees.

### Proof of Concept
See `tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs:194-269`: `simulation_records_the_rogue_pool_wallet_transfer_under_the_callers_swap_collateral_entry` shows simulation recording `wallet_token.transfer(alice, attacker, WALLET_BALANCE)` beneath Alice's `swap_collateral` root; `enforced_auth_moves_the_wallet_token_only_when_the_signed_tree_lists_the_rogue_transfer` shows signing that tree drains Alice's wallet to zero while her ETH swap still settles fairly.

Note: the repo documents this hazard in `docs/explanation/threat-model.md:154-165`, so this may be classified as a documented/accepted design trade-off rather than a new defect under the program's policy.