### Title
Unallowlisted route venues let arbitrary hop code piggyback on the caller's signed auth tree and drain their wallet - (File: contracts/swap-aggregator/src/venues/mod.rs)

### Summary
The bug class is "untrusted code executing inside a privileged security context." In the OpenLIT report, `pull_request_target` ran fork-supplied code with the base repo's write token and secrets. The XOXNO analog is the swap-aggregator route hop: `execute_strategy` accepts a caller-supplied `swap_xdr` that names arbitrary pool and token contract addresses, and the router invokes that untrusted code while the caller's `require_auth` authorization is on the stack. A token `transfer` issued by the rogue hop contract from the caller is recorded by the host as a child of the caller's own auth entry, so if the caller signs the simulated tree, the rogue contract moves tokens that were never part of the swap — the caller's entire wallet, not just the routed input.

### Finding Description
`execute_strategy(sender, total_in, swap_xdr)` performs `sender.require_auth()` and then executes the decoded program. There is no allowlist of pool or token addresses: `dispatch_hop` in `contracts/swap-aggregator/src/venues/mod.rs` invokes `hop.pool` and `hop.token_in`/`hop.token_out` exactly as the payload names them. The threat model explicitly confirms the exposure: "The router calls the pool and token addresses its payload names and keeps no allowlist of them, so a route can put third-party code on the call stack below the caller's authorization. A token transfer that such code makes from the caller is recorded by an honest simulation as a child of the caller's authorization entry, and it executes if the caller signs that tree. The loss is then the caller's wallet, not the routed amount, and neither the payload minimum nor the final risk gate bounds it" (`docs/explanation/threat-model.md:154-165`).

The harness test `tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs` proves the mechanism end-to-end: an attacker-registered `RogueHopPool` contract whose `swap` entrypoint calls `token.transfer(alice, attacker, WALLET_BALANCE)` for a token the protocol never listed; the recorded auth tree attaches the theft as a `sub_invocation` of Alice's `swap_collateral` (or `execute_strategy`) entry, and enforcing mode executes it once signed — `balance(alice) == 0`, `balance(attacker) == WALLET_BALANCE`.

The same exposure exists through the controller strategy verbs (`swap_collateral`, `swap_debt`, `repay_debt_with_collateral`, `multiply`), which forward opaque `routeXdr` bytes to the router without decoding them (`skills/xoxno-swap-aggregator/composition.md: "the controller forwards those bytes to the router as swap_xdr without decoding them"`), so a single signature on a controller verb can carry the same poisoned child.

### Impact Explanation
Theft of user funds beyond the routed amount: the rogue hop contract can transfer any token the victim holds — including tokens unrelated to the lending protocol — to the attacker. Neither the router's `min_out`/`SlippageExceeded` check, the measured-delta accounting in `dispatch_hop`, nor the controller's `RouterOverspend`/`NoSwapOutput`/final-HF gates bounds the loss, because the stolen transfer is a sibling auth entry, not part of the measured hop flow. The protocol's residual caps and positive-output checks still pass since the hop itself can return a fair output.

### Likelihood Explanation
Requires the victim to sign a simulated authorization tree containing an unexpected child `transfer` — i.e., the attacker must get a malicious route in front of the victim (a compromised/phis­hing route source, or any dapp that does not decode the route). No privileged role, no timing, and no protocol state is needed; the contracts provide the privileged context (the caller's auth) by design. The threat model assigns mitigation to the client ("a client must decode the route it signs and refuse an authorization tree with any other child"), but the contract neither enforces a venue allowlist nor constrains what hop code may do under the caller's authorization, so every user that relies on blind or server-generated simulation is exposed. Medium likelihood, critical-scale per-victim impact.

### Recommendation
Enforce an on-chain allowlist of venue pool contracts (governance-managed, as already done for Blend pool approvals), or at minimum reject hop `pool`/`token` addresses that are not the venue contract type the opcode claims. Alternatively, execute hops in a context where the sender's auth cannot be extended — e.g., pull the input, drop the sender requirement, and perform venue calls under a router-internal frame — so that recording mode cannot attach foreign transfers to the caller's entry. Until then, ship and enforce mandatory route-tree verification in the SDK (the `verifyRouteBytes` helper exists but is opt-in).

### Proof of Concept
```rust
// Attacker-deployed hop "pool" (mirrors tests/test-harness/tests/strategy/
// rogue_hop_pool_transfer_joins_caller_auth_tree.rs, RogueHopPool)
#[contractimpl]
impl RogueHopPool {
    pub fn swap(env: Env) {
        let (victim, wallet_token, to, amount): (Address, Address, Address, i128) =
            env.storage().instance().get(&symbol_short!("PLAN")).unwrap();
        // Executes under the *victim's* auth entry once they sign the simulated tree.
        token::Client::new(&env, &wallet_token).transfer(&victim, &to, &amount);
    }
}
```

1. Attacker registers `RogueHopPool` with `PLAN = (victim, victim's_token, attacker, full_balance)`.
2. Attacker hands the victim a `swap_xdr`/`routeXdr` whose hop `pool` is the rogue contract (or composes it via `controller.swap_collateral(caller, account_id, in_key, amount, out_key, route)`).
3. Victim's client simulates: the host records `token.transfer(victim, attacker, balance)` as a `sub_invocation` of the victim's `swap_collateral`/`execute_strategy` auth entry.
4. Victim signs the tree; enforcing mode executes the transfer. The hop can simultaneously return a fair swap output, so `dispatch_hop`'s `ZeroOutput`/`InvalidAmount` checks, the router min-out check, and the controller's post-swap HF gate all pass. Result: victim's entire wallet balance of the targeted token moves to the attacker, while the swap itself appears to settle normally.