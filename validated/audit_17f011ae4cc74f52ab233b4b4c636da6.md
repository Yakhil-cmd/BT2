### Title
Attacker-controlled route bytes let arbitrary venue code execute token transfers under the signer's authorization tree - (File: contracts/controller/src/strategies/swap.rs)

### Summary
The XXE class — a privileged component blindly processing attacker-supplied structured input that causes unintended privileged side effects — maps directly onto the controller's route handling. `swap_collateral`, `swap_debt`, `multiply`, and `repay_debt_with_collateral` accept caller-supplied `StrategySwap` bytes and forward them verbatim to the configured router (`swap.rs:34-38`). Neither the controller nor the router keeps an allowlist of the addresses a route names, so a crafted payload can place attacker-deployed code on the call stack *below* the victim's `require_auth` entry. On Soroban, any `token.transfer(victim, attacker, amount)` such code performs is recorded as a child of the victim's own signed authorization tree and executes. This is the exact analog of external entities being resolved under the parser's privileges.

### Finding Description
`swap_tokens` in `contracts/controller/src/strategies/swap.rs:13-55` authorizes only the controller's exact input transfer to the router, then calls `router.execute_strategy(&controller, &amount_in, swap)` with the raw caller-provided payload. `process_swap_collateral` (`strategies/swap_collateral.rs:40-47`) gates on `require_authorized_caller` and `require_owner_or_delegate`, so the victim (or their delegate) signs the controller call, but the payload content is unconstrained. The threat model confirms the consequence: "a route can put third-party code on the call stack below the caller's authorization... The loss is then the caller's wallet, not the routed amount, and neither the payload minimum nor the final risk gate bounds it" (`docs/explanation/threat-model.md:154-165`). The test `tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs:62-71, 194-227` proves it end-to-end: a rogue "pool" named by the route calls `token.transfer(victim, attacker, amount)` for a token the protocol never listed, the recorded auth tree attaches that transfer under the victim's `swap_collateral` entry, and in enforcing mode the signed poisoned tree executes it.

### Impact Explanation
Theft of user funds. The crafted payload drains arbitrary tokens held in the victim's wallet — not just the routed amount or protocol balances. In the PoC the victim's entire `WALLET_BALANCE` (77,770 units of an unrelated token) is moved to the attacker in the same transaction that otherwise produces a fair swap output and passes all of the controller's risk gates. Neither `RouterOverspend`/`NoSwapOutput` nor `verify_router_output` bounds the loss because the theft happens in a parallel auth-tree branch, not in controller-measured balances.

### Likelihood Explanation
Medium. Exploitation requires the victim to sign a transaction whose simulated auth tree contains the injected transfer. The protocol's own design surfaces exactly this path: route bytes come from an off-chain quote service (`skills/xoxno-lending-contracts/composing.md:39-40`), and `simulateTransaction` produces the auth tree a wallet signs — a compromised or malicious route provider, frontend, or delegate embeds the rogue hop and the simulation silently records the poisoned child. An attacker-deployed pool contract plus a crafted route is fully within an unprivileged user's reach; the only mitigation is client-side auth-tree inspection, which is an off-chain control. This mirrors CVE-2018-1000198's model (low-privilege attacker feeds crafted input to a privileged processor).

### Recommendation
- Enforce a venue/pool allowlist: governance-registered pool addresses per opcode, rejecting payload references to unregistered contracts before dispatch.
- Alternatively/additionally, isolate route execution: have the router perform venue calls under its own contract-auth-only subcontext so no `require_auth` node for the caller can be on the stack when third-party code runs (e.g., pre-pull input to the router in a separate transaction shape, or dispatch hops via a child contract with no caller auth).
- Document for integrators that signing must be rejected when the simulated auth tree contains any child beyond the single expected input transfer; ship a reference decoder.

### Proof of Concept
Already demonstrated by the in-repo harness:

```rust
// RogueHopPool named by the route performs the theft (rogue_hop_pool_transfer_joins_caller_auth_tree.rs:62-71)
pub fn swap(env: Env) {
    let (victim, wallet_token, to, amount): (Address, Address, Address, i128) = /* stored plan */;
    if amount > 0 {
        token::Client::new(&env, &wallet_token).transfer(&victim, &to, &amount);
    }
}
```

1. Attacker deploys `RogueHopPool` configured with `(victim, victim's wallet token, attacker, amount)` and a router double (or any route venue the production router will call) that pays a fair output, so all controller checks pass.
2. Victim calls `swap_collateral(alice, account_id, USDC_key, 5_000e7, ETH_key, route)` where `route.hop_pool` is the rogue contract.
3. Simulation records `token.transfer(alice → attacker, WALLET_BALANCE)` as a child of Alice's `swap_collateral` auth entry; the test asserts `recorded == [(alice, poisoned_root)]`.
4. In enforcing mode, the signed tree authorizes the transfer: `wallet(alice) == 0`, `wallet(attacker) == WALLET_BALANCE`, while `supply_balance_raw(ALICE, "ETH") == FAIR_OUT_ETH` — the swap itself looks completely legitimate.

Caveat: the exposure is acknowledged in `docs/explanation/threat-model.md`, which prescribes client-side auth-tree decoding as the mitigation; the finding stands because the on-chain code itself provides no venue allowlist or auth isolation, leaving the theft path reachable through every in-scope strategy entrypoint that accepts route bytes.