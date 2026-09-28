### Title
Crafted swap route can steal unrelated wallet tokens through poisoned authorization tree - ([File: contracts/controller/src/strategies/swap.rs])

### Summary
Controller strategy calls pass attacker-controlled route bytes to the configured router after authorizing only the intended input-token transfer. The router permits arbitrary pool addresses in its route registry, so a malicious venue contract can execute a `token.transfer(victim, attacker, amount)` while the victim's root authorization is active. Transaction simulation records that unexpected transfer as a child authorization; if the victim signs the poisoned tree, the transfer executes and the strategy can still pass all controller accounting checks.

### Finding Description
`swap_collateral` accepts caller-provided `swap` bytes and forwards them through `SwapCollateralParams` without venue allowlisting. The strategy layer invokes `router.execute_strategy(&controller, &amount_in, swap)` inside `swap_tokens`, then only verifies that the controller did not overspend `token_in` and received positive `token_out`. It does not constrain what other calls occur beneath the router or what additional sub-invocations appear in the caller's authorization tree. The router decodes pool addresses from the route's `assets` registry and dispatches them by venue. A malicious contract can implement the selected pool ABI, consume/produce the expected balances, and additionally transfer an unrelated token from the victim to the attacker.

The repository's enforcement-mode regression test demonstrates this auth propagation: recording simulation attaches `wallet_token.transfer(alice, attacker, WALLET_BALANCE)` beneath Alice's `swap_collateral` authorization, while enforced auth succeeds only when the signed tree includes that transfer. After signing it, Alice's unrelated wallet balance is drained while the protocol receives fair ETH output.

### Impact Explanation
Theft of user funds. The stolen amount is not limited to the routed input or position collateral: the malicious venue can transfer any unrelated token balance held by the victim, provided that transfer is included in the signed authorization tree. A malicious route can still satisfy minimum output and controller risk checks, making the poisoned transaction appear economically successful while draining external wallet assets.

### Likelihood Explanation
Likelihood is Medium. Exploitation requires a victim to submit a crafted route and sign the resulting authorization tree, but this fits ordinary swap UX where route XDR is generated off-chain and authorization trees may not be decoded carefully by clients. No protocol privilege, leaked key, oracle manipulation, or contract upgrade is required; the attacker only needs to deploy a route-compatible venue and induce the victim to use it.

### Recommendation
Do not rely on users to inspect poisoned authorization trees. Restrict swap routes to an on-chain allowlist or registry of approved venue pool addresses, or verify venue identity from a trusted registry before dispatch. At minimum, add a protocol-side authorization-shape guard if Soroban exposes a suitable mechanism, and update clients/simulation tooling to hard-reject any child authorization other than the expected exact input-token transfer.

### Proof of Concept
1. Victim supplies USDC and owns an unrelated wallet token not listed by the lending protocol.
2. Attacker deploys a malicious contract implementing the route's selected pool ABI. Its swap implementation performs a normal-looking exchange but also calls `token::Client::transfer(victim, attacker, victim_balance)` on the unrelated token.
3. Attacker encodes route bytes whose `assets` registry includes the malicious pool address.
4. Victim calls `Controller::swap_collateral(caller=victim, account_id, current=USDC market, amount, new=ETH market, swap=route)`.
5. Controller invokes `router.execute_strategy`; router dispatches to the malicious pool.
6. Simulation records the malicious unrelated-token transfer as a child of the victim's `swap_collateral` authorization.
7. Victim signs the poisoned tree. The malicious pool steals the unrelated token while returning enough ETH for `dispatch_hop` and `verify_router_output` to succeed.
8. The transaction commits: victim receives swap output and an updated collateral position, but their unrelated wallet token has been transferred to the attacker.