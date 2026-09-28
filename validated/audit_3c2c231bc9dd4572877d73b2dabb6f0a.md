### Title
Route-supplied pool address injects arbitrary contract calls under the caller's authorization tree, enabling theft of the signer's wallet funds - (File: contracts/swap-aggregator/src/venues/mod.rs)

### Summary
The OpenEMR bug class is attacker-controlled input reaching an execution sink in an authenticated context. The analog here: `execute_strategy` decodes hop `pool`/`token` addresses from the caller-supplied `StrategyPayload` (`assets` registry) with no allowlist, and `dispatch_hop` invokes whichever contract the payload names. A rogue "pool" contract placed inside a route runs below the caller's `require_auth` entry and can attach additional `token.transfer(victim → attacker, amount)` sub-invocations to that same signed tree — the Soroban analog of command injection. A working reproduction exists in `tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs`.

### Finding Description
- The route's address registry is fully attacker/client-controlled: `SwapPayload.assets` holds tokens and pools indexed by each 5-byte instruction (`contracts/swap-aggregator/src/types.rs:38-45`; wire layout in `skills/xoxno-swap-aggregator/payload.md`).
- `execute_op` builds `SwapHop { pool: assets[idx_a], token_in: assets[idx_b], token_out: assets[idx_c] }` and calls `venues::dispatch_hop` (`contracts/swap-aggregator/src/execute/mod.rs:152-165`).
- `dispatch_hop` invokes `hop.pool` through the venue adapter (e.g. `phoenix.rs` calls `invoke_contract(&hop.pool, "swap", ...)`). There is no check that `pool` is a known venue contract — the opcode only selects the adapter, not the target.
- While that pool code is on the stack, any `require_auth`-gated call it makes on the `sender` (the end user, or a contract sender) is recorded as a child of the caller's authorization entry. The test proves the recording: `token::Client::transfer(victim, attacker, WALLET_BALANCE)` inside a `RogueHopPool::swap` lands as a `sub_invocations` child of Alice's `swap_collateral` root and executes once she signs the simulated tree, draining 77,770 of an unrelated wallet token.
- Neither the payload `min_out`, the controller's `RouterOverspend`/`NoSwapOutput` measured-delta checks (`contracts/controller/src/strategies/swap.rs:29-54`), nor the final health-factor gate bounds this: the stolen transfer is a wallet transfer, not part of the routed amounts.

### Impact Explanation
Theft of user funds. Any token balance in the signer's wallet — including assets the protocol never lists — can be transferred to the attacker in the same transaction. The measured swap can even be made fair-looking so the route passes all protocol gates and the position still finalizes solvent.

### Likelihood Explanation
Execution requires the victim to sign an authorization tree that visibly contains the extra `transfer` sub-invocation; an honest simulation surfaces it. However, route bytes come from an off-chain quote service and users routinely sign whatever `simulateTransaction` records, so a malicious or compromised route source, a phishing frontend, or a hostile integration contract can deliver a poisoned `routeXdr`. The protocol itself provides no defense: no venue/pool allowlist, no bound on child auth entries, and the threat model (`docs/explanation/threat-model.md:154-165`) pushes verification entirely onto the client. Reachable by any unprivileged address through `execute_strategy` directly or via the controller strategy verbs.

### Recommendation
Maintain an on-chain allowlist of venue pool addresses (governance-managed) and reject hops whose `pool` is not listed, or authenticate venue contracts by deployed WASM hash. Short of that, bound the authorization surface: document-and-enforce at the SDK/wrapper level that a strategy auth tree may contain only the single input `transfer` child, and have `execute_strategy` reject payloads that would produce additional `require_auth` calls against the sender where feasible.

### Proof of Concept
`tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs` demonstrates it end-to-end:

1. Attacker deploys `RogueHopPool`, a contract whose `swap()` calls `token::Client::transfer(victim, attacker, amount)` on an unrelated wallet token (lines 51-72).
2. A route is built whose `hop_pool` is the rogue contract while `token_in`/`token_out` and `min_out` are legitimate (lines 111-125).
3. Alice invokes `swap_collateral` (or `execute_strategy` directly). In recording mode the rogue transfer attaches beneath her root auth entry; the test asserts the recorded tree equals Alice's `swap_collateral` entry with `transfer(alice, attacker, WALLET_BALANCE)` as a child (lines 195-222).
4. Once Alice signs that tree (enforcing mode test `try_swap_with_signed_tree`, lines 166-183), execution succeeds: `wallet(alice) == 0`, `wallet(attacker) == WALLET_BALANCE`, and the swap itself still delivers `FAIR_OUT_ETH` (lines 224-226).