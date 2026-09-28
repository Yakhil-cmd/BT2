### Title
Attacker-crafted swap routes can invoke arbitrary "pool" contracts that attach malicious `token.transfer` calls to the caller's signed auth tree, draining wallet tokens beyond the routed amount - (File: contracts/controller/src/strategies/swap.rs)

### Summary
The analog of CVE-2019-25017 (client trusting server-chosen object names, validating only superficially) is the controller's route handling: the user-supplied `StrategySwap` payload names the pool/token addresses the router calls, and no on-chain component validates those names. `swap_tokens` in `contracts/controller/src/strategies/swap.rs:13-55` forwards the payload verbatim to `router.execute_strategy`; the router's `dispatch_hop` (`contracts/swap-aggregator/src/venues/mod.rs:34-40`) invokes whatever `hop.pool` the payload declares. A malicious "pool" contract executed inside the route can call `token.transfer(victim, attacker, amount)`; because the call sits below the victim's `require_auth` invocation, the host records it as a child of the victim's authorization entry during simulation, and the signed tree authorizes it at execution time.

### Finding Description
The bug class is "downstream consumer trusts an externally-chosen name and performs only cursory validation." Here the externally-chosen names are the venue pool and token addresses inside the `StrategySwap`/`StrategyPayload` registries, and the "client" is the user's Soroban authorization tree.

- `swap_tokens` authorizes only the exact input transfer to the router (`authorize_transfer_as_current`, line 34) and then executes the attacker-influenced `swap` payload under the flash guard (lines 36-38). It validates balances, not route identities.
- The router keeps no allowlist of pool/token addresses: `SwapHop.pool`, `token_in`, `token_out` come straight from the payload's `assets` registry (`contracts/swap-aggregator/src/types.rs:25-45`).
- The threat model itself states the consequence: "a route can put third-party code on the call stack below the caller's authorization. A token transfer that such code makes from the caller is recorded by an honest simulation as a child of the caller's authorization entry, and it executes if the caller signs that tree. The loss is then the caller's wallet, not the routed amount" (`docs/explanation/threat-model.md:154-165`).
- The harness test `tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs` demonstrates end-to-end via `swap_collateral`: a `RogueHopPool` whose `swap()` does `token.transfer(alice, attacker, WALLET_BALANCE)` succeeds and empties Alice's balance of a token the protocol never listed, when the returned (poisoned) auth tree is signed (lines 229-269). With an honest root-only tree the host rejects it, proving nothing on-chain filters the route.

Reachable entrypoints: `swap_collateral`, `swap_debt`, `repay_debt_with_collateral`, `multiply`, and `flash_position` — every path that funnels into `swap_tokens`/`swap_tokens_or_passthrough` — plus direct `execute_strategy` calls.

### Impact Explanation
Theft of user funds. Unlike a bad-price swap bounded by `total_min_out` and the controller's measured output check (`verify_router_output`, lines 75-84), the stolen transfer is unrelated to the routed tokens: the rogue hop pool can move any token the victim holds to any recipient, so the loss equals the victim's whole wallet balance of any asset, bounded only by what the payload author chooses to steal. The controller's `RouterOverspend`/`NoSwapOutput` checks and final health-factor gate do not constrain it, exactly mirroring CVE-2019-25017 where the server-chosen filename escapes the client's directory-traversal-only validation and can overwrite `.ssh/authorized_keys`.

### Likelihood Explanation
Requires a victim to sign a poisoned authorization tree — analogous to the CVE's high attack complexity (malicious/MITM server plus client-side trust). Exploitation path: a malicious or compromised route provider, phishing frontend, or manipulated quote returns a route whose `assets` registry names an attacker-deployed contract as a hop pool. Simulation produces an auth tree containing the rogue `transfer` as a child invocation; wallets that sign simulated trees without per-invocation inspection approve it, and the swap then executes "fairly" (the rogue pool can even return correct output so all min-out checks pass) while the theft rides along. The dedicated test confirms both halves: unsigned tree → host rejection; signed tree → full theft. No privileged role, key leak, or oracle manipulation is needed.

### Recommendation
Enforce route identity validation on-chain rather than relying on the client to decode the tree:
- Maintain a governance/operator-controlled allowlist of legitimate venue pool addresses, and reject hops whose `hop.pool` is not allowlisted before `dispatch_hop` invokes it (add the check in `contracts/swap-aggregator/src/venues/mod.rs` or during `Program::decode` in `contracts/swap-aggregator/src/program.rs`).
- Alternatively/additionally, constrain auth trees: the controller could assert that `execute_strategy` adds no child invocations beyond the single authorized input transfer, or clients must reject any simulated tree with children other than the expected `token_in.transfer`.
- Document the wallet-side requirement: refuse authorization trees containing transfers of tokens outside the declared route assets.

### Proof of Concept
See `tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs`:

1. Deploy `RogueHopPool` initialized with `(victim=alice, token=wallet_token, to=attacker, amount=WALLET_BALANCE)`; its `swap()` performs `token::Client::new(&env, &wallet_token).transfer(&victim, &to, &amount)` (lines 54-72).
2. Build a `swap_collateral(alice, account_id, usdc, 50_000_000_000, eth, route)` call whose route names `RogueHopPool` as `hop_pool` while paying a fair `min_out` (lines 111-125) — so every slippage/min-out check passes.
3. Simulate: the host records the rogue `wallet_token.transfer(alice → attacker, 77_770_000_000)` as a child of Alice's auth entry (lines 259-264).
4. Sign the simulated tree and submit: the call succeeds; `balance(alice, wallet_token)` goes from `77_770_000_000` to `0` and `balance(attacker)` becomes `77_770_000_000`, while Alice's supplied USDC and the fair ETH output are untouched (lines 265-269). The control run with a root-only honest tree is refused with a host auth error and rolls back (lines 240-256), confirming the theft rides entirely on the unvalidated route-named contract plus the signed tree.