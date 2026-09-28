### Title
Attacker-supplied route pool invokes arbitrary contract under the swap caller's authorization, draining the caller's wallet - (File: contracts/controller/src/strategies/swap.rs)

### Summary
The command-injection analog: the controller passes a fully attacker-constructed `StrategySwap` payload to the swap router, and the venue/pool addresses named inside it are invoked without any allowlist. A malicious "pool" contract named by the route can execute `token.transfer(victim, attacker, amount)` for any token the victim holds. Because Soroban simulation records that nested call as a child of the victim's `swap_collateral`/`swap_debt`/`repay_debt_with_collateral`/`multiply` authorization entry, signing the simulated auth tree (the standard wallet flow) silently authorizes the theft — exactly like attacker-controlled data reaching a shell.

### Finding Description
`swap_tokens` in `contracts/controller/src/strategies/swap.rs:13-55` forwards the caller-supplied `swap` payload to the router via `router.execute_strategy(&controller, &amount_in, swap)`. It only authorizes one exact input transfer and checks balance deltas afterward (`in_after <= in_before`, `received > 0`); it never inspects which contracts the route calls.

The router dispatches hops to whatever pool/token addresses the payload's `assets` registry names — there is no venue or pool allowlist (`contracts/swap-aggregator/src/venues/mod.rs:34-40` and `docs/explanation/threat-model.md:154-165`: "a route can put third-party code on the call stack below the caller's authorization"). A rogue pool contract invoked this way runs `token::Client::transfer(&victim, &attacker, &amount)`, which requires the victim's auth. `simulateTransaction` records that nested transfer as a child of the victim's top-level controller authorization; when the victim signs the returned tree, the host executes it.

The harness test `tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs` proves both halves: `simulation_records_the_rogue_pool_wallet_transfer_under_the_callers_swap_collateral_entry` (lines 194-227) shows the recorded auth tree containing `transfer(alice, attacker, WALLET_BALANCE)` nested under `swap_collateral`, with Alice's wallet drained; `enforced_auth_moves_the_wallet_token_only_when_the_signed_tree_lists_the_rogue_transfer` (lines 230-269) shows the signed poisoned tree executes the theft while the fair swap still completes, so every downstream balance check passes.

### Impact Explanation
Theft of user funds. The attacker steals any token balance in the victim's wallet — not just the routed `amount_in` — because `verify_router_output` and the `RouterOverspend` check only measure the swap tokens, and the route returns fair output so the position ends healthy. Loss is unbounded up to the victim's full wallet balances.

### Likelihood Explanation
A single unprivileged attacker deploys a `RogueHopPool`-style contract, builds a `StrategySwap` naming it, and gets the victim to submit it via `swap_collateral`, `swap_debt`, `repay_debt_with_collateral`, or `multiply` — e.g., by serving the route through a compromised or malicious quote/frontend channel, the same way routes are normally distributed (built off-chain per `contracts/swap-aggregator/README.md:3-5`). The theft succeeds whenever the victim signs the simulated authorization tree without decoding every child entry, which is the default signing flow; the fair output makes the transaction look benign.

### Recommendation
Maintain an on-chain allowlist of venue pool/share-token addresses in the swap-aggregator and reject hops whose `assets` entries are not registered, or have the controller pin the set of contracts a route may invoke. Until then, clients must decode the route and refuse any authorization tree with children beyond the expected input transfer — a mitigation most wallets do not perform.

### Proof of Concept
`tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs` contains the working exploit: `RogueHopPool::swap` (lines 62-72) transfers `WALLET_BALANCE` of an unrelated token from Alice to the attacker; Alice calls `swap_collateral` with a route through that pool; simulation returns the poisoned tree containing the theft as a child of her `swap_collateral` entry; signing that tree leaves Alice's wallet at 0 and the attacker at `WALLET_BALANCE`, while `supply_balance_raw(ALICE, "ETH")` shows the fair `FAIR_OUT_ETH` output was still credited.