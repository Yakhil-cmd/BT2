### Title
Malicious route hop attaches a wallet-draining `token.transfer` to the caller's signed auth tree in controller swap strategies — (File: contracts/controller/src/strategies/swap.rs)

### Summary
The Nexus Mutual incident class is "permission stolen": the attacker deceived the victim into signing a transaction whose real effect differed from what the victim believed they were authorizing. XOXNO Lending has the same bug class on-chain: controller strategy entrypoints (`swap_debt`, `swap_collateral`, `repay_debt_with_collateral`, `multiply`, `flash_position`) let the caller supply an arbitrary `StrategySwap` route, the router keeps no allowlist of hop pools, and any third-party pool placed on the call stack below the caller's `require_auth` can invoke `token.transfer(caller, attacker, amount)`. Simulation records that transfer as a child of the caller's own authorization entry, so a victim who signs the simulated tree authorizes the theft of their entire wallet balance of any token — far beyond the routed amount and unbounded by min-out or the controller's post-swap risk gates.

### Finding Description
`swap_tokens` in `contracts/controller/src/strategies/swap.rs` accepts a caller-provided `swap` payload and forwards it to the router via `router.execute_strategy(&controller, &amount_in, swap)` inside the same transaction as the caller's `require_auth`. The router decodes the payload and calls whatever pool address the `assets` table names — there is no venue or pool allowlist (INV-STRAT-02/03 note the whitelist only selects fee placement). Because Soroban records every `require_auth` under the top-level signer's authorization tree, a rogue hop pool calling `token.transfer(victim, attacker, victim_balance)` causes simulation to append that invocation to the tree the wallet displays for signing. The test `tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs` demonstrates both directions: with an honest root-only tree the host refuses the rogue transfer, and with the simulated (poisoned) tree the same route moves the victim's entire `WALLET_BALANCE` to the attacker — including a token the protocol never listed.

### Impact Explanation
Theft of user funds. The stolen amount is the victim's full wallet balance of whatever token the rogue hop targets, not the strategy's routed `amount_in`. Neither the route's declared minimum output nor the controller's final health/LTV gates bound it, because the drain happens inside the signed auth tree, not through the strategy accounting. This mirrors the Karp incident exactly: a deceived signature authorizes a transfer the user never intended.

### Likelihood Explanation
Medium. Exploitation requires the victim to sign a transaction containing the poisoned authorization tree — the same precondition as the reference incident (attacker-controlled front-end, quote server, or phishing flow that supplies the `swap_xdr` route). No privileged role, key leak, or contract flaw beyond the unallowlisted venue dispatch is needed; any unprivileged address can reach the vulnerable path through `swap_collateral`/`swap_debt`/`repay_debt_with_collateral`/`multiply` or a direct `execute_strategy` call. The exposure is documented in `docs/explanation/threat-model.md` ("Routes, callbacks, and external integrations"), which places mitigation on the client rather than the contract, so on-chain the primitive remains exploitable.

### Recommendation
Constrain what can ride on the caller's authorization: allowlist route venue/pool addresses (e.g., governance-approved pools per venue, mirroring the Blend approval list), or dispatch hops through a mechanism that cannot attach user-auth sub-invocations. At minimum, surface a canonical check in the SDK/router so that any authorization tree containing a child beyond the single input `token_in.transfer` is rejected before signing, and document the residual risk for routes constructed off-platform.

### Proof of Concept
`tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs` lines 229–269 implement it end-to-end:

1. `Scene` registers a rogue hop pool whose `swap` implementation calls `token.transfer(alice, attacker, WALLET_BALANCE)` for an unlisted wallet token.
2. A route through that pool is submitted with an honest root-only auth tree → host rejects with `Unauthorized function call`, wallet intact.
3. The same route is re-simulated and the resulting tree (which now includes the rogue `transfer` as a child of the caller's entry) is signed → the call succeeds and `s.wallet(&s.alice) == 0`, `s.wallet(&s.attacker) == WALLET_BALANCE`.

Reproduced via any controller strategy entrypoint that accepts a `StrategySwap` (e.g., `swap_collateral(caller, account_id, collateral, debts, swap)`) with a payload naming the rogue pool; the victim only has to sign the simulation-produced transaction.