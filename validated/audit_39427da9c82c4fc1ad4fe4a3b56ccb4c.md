### Title
Unallowlisted swap-route venues can hide a wallet-draining `transfer` inside the user's `swap_collateral`/`multiply` authorization tree - (File: contracts/swap-aggregator/src/execute/mod.rs)

### Summary
The bug class: a user approves a request whose displayed scope hides the actual access granted (a wallet prompt that silently authorizes reading all vault credentials). In XOXNO Lending, a user who submits a quote-server route to a controller strategy (`swap_collateral`, `multiply`, `swap_debt`, `repay_debt_with_collateral`) signs one authorization tree for the top-level call. Because the router keeps no allowlist of venues, the route's payload can name an attacker-controlled "pool" contract as a hop venue. That rogue pool executes arbitrary code below the caller's authorization and can invoke `token.transfer(caller, attacker, amount)` on any token — including tokens the protocol never listed. In recording/simulation mode the host attaches that transfer as a child of the caller's auth entry, so a wallet that signs the simulated tree (without decoding every sub-invocation) unknowingly authorizes a full wallet drain, exactly mirroring the hidden-scope disclosure bug in the report.

### Finding Description
`execute_strategy` (`contracts/swap-aggregator/src/execute/mod.rs:51`) requires only `sender.require_auth()` and then dispatches hops to whatever pool addresses the route's `assets` registry names; there is no venue allowlist. The controller path (`contracts/controller/src/strategies/swap.rs:34-38`) authorizes one exact input transfer to the router and calls `execute_strategy` under a flash guard, so the user's single signature on `swap_collateral` covers everything the route does below it. The codebase's own threat model and harness confirm the consequence: "a route can put third-party code on the call stack below the caller's authorization … The loss is then the caller's wallet, not the routed amount" (`docs/explanation/threat-model.md:154-165`), and the test `tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs` shows a malicious hop pool transferring a victim's whole 77,770-unit balance of an unlisted wallet token, recorded as a child of the victim's `swap_collateral` auth entry — and executing in enforcing mode only because the victim signed the tree the simulation returned.

### Impact Explanation
Theft of user funds: a victim who signs a poisoned route authorizes `token.transfer(victim, attacker, amount)` for any token in their wallet, independent of the swap size, slippage parameter, or final account health check. `WALLET_BALANCE = 77_770_000_000` of a never-listed token moves to the attacker while the swap itself still settles normally, so the victim's position looks healthy.

### Likelihood Explanation
The route bytes are opaque packed XDR produced off-chain (per `skills/xoxno-swap-aggregator/payload.md`, clients are told to use `routeXdr` as-is). Any unprivileged attacker can deploy a pool-shaped contract and get a victim's client/quote source to embed it as a venue. The exploit needs no privileged role, leaked key, or oracle manipulation — only a signed authorization tree that simulation helpfully populates with the rogue transfer. The only defense is client-side decoding of every auth sub-invocation, which the threat model itself places on the wallet rather than the contract.

### Recommendation
Constrain route venue addresses to a governance-maintained allowlist (the router already keeps a token whitelist for fee placement; extend a similar registry to pools), or require each venue address in `assets` to be registered. At minimum, the controller could reject routes referencing pools not on an approved list, so third-party code can never execute under the user's authorization. Client-side auth-tree inspection (the current documented mitigation) is the same class of fix as the pallad patch — disclosure — and leaves the on-chain scope unrestricted.

### Proof of Concept
See `tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs`:

- A `Scene` builds a `swap_collateral` route whose hop pool is an attacker contract that, inside the venue call, executes `wallet_token.transfer(alice, attacker, WALLET_BALANCE)`.
- `simulation_records_the_rogue_pool_wallet_transfer_under_the_callers_swap_collateral_entry` (lines 195–227): recording mode attaches the stolen transfer as `sub_invocations[0]` of Alice's `swap_collateral` auth entry; Alice's wallet goes to 0, attacker receives `WALLET_BALANCE`.
- `enforced_auth_moves_the_wallet_token_only_when_the_signed_tree_lists_the_rogue_transfer` (lines 230–269): an honest root-only tree fails (host auth rejection), but the tree simulation produced — which includes the rogue transfer — executes and drains the wallet.

The attacker's sole cost is deploying the malicious pool contract; the victim only ever sees one signature prompt for `swap_collateral`.