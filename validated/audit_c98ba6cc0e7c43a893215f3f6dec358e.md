### Title
Router executes user-supplied pool/token contract addresses with no allowlist, letting a route put attacker code on the victim's authorization tree to drain wallet funds — (File: contracts/swap-aggregator/src/venues/mod.rs)

### Summary
The media-loader report is "the server fetches/invokes a request-supplied resource with no host validation" (SSRF / local file read). The on-chain analog in XOXNO Lending is the swap router executing **request-supplied contract addresses** with no allowlist: every hop's `pool`, `token_in`, `token_out`, and every `assets` entry are taken verbatim from the caller's `swap_xdr` payload and invoked mid-settlement. A malicious venue/pool contract called inside a route can emit a `token.transfer(victim, attacker, x)` that the Soroban host records as a child of the victim's `require_auth` entry, so a signature on the simulated auth tree authorizes transfers of tokens unrelated to the swap — draining the signer's wallet, not just the routed `total_in`.

### Finding Description
- `dispatch_hop` calls whatever venue adapter and pool address the hop names; venue adapters call the `pool` address directly from the payload (`contracts/swap-aggregator/src/venues/mod.rs:23-40`). The dispatcher validates only measured balance deltas (`ZeroOutput`/`InvalidAmount`), never address identity.
- The address registry (`assets: Vec<Address>`) and hop pools come entirely from the caller's `StrategyPayload` (`contracts/swap-aggregator/src/types.rs`; decoded in `lib.rs` via `StrategyPayload::from_xdr`). There is no venue, pool, or token allowlist — confirmed by `docs/reference/invariants.md` INV-STRAT-03 and `docs/explanation/threat-model.md:154-165`, which states the router "keeps no allowlist" and a route "can put third-party code on the call stack below the caller's authorization."
- This is proven by the pinned harness test `tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs`: `RogueHopPool::swap` calls `token::Client::transfer(&victim, &to, &amount)` for a token the protocol never listed, and the host attaches that transfer to the caller's auth entry.
- The controller's own delegated strategies are safe (INV-STRAT-01 binds one exact input-transfer invocation with no sub-invocations), but direct `execute_strategy` callers get no such protection: the threat model itself notes "the direct `execute_strategy` path has the same exposure for every swap user."

### Impact Explanation
Theft of user funds. An attacker (malicious quote/route provider, phishing site, or compromised route source) supplies a `routeXdr` whose hop pool is attacker code. Simulation records the injected `token.transfer(victim → attacker)` as a child of the victim's authorization; if the victim signs the envelope (the standard "sign what simulation produced" flow), arbitrary wallet tokens — unrelated to the swap and unbounded by `total_in`, `min_out`, or the controller's risk gates — are transferred. Neither the payload minimum nor measured-delta checks bound this loss.

### Likelihood Explanation
Medium. Exploitation requires the victim to submit an attacker-constructed route and sign the poisoned auth tree — the transfer is visible in simulation, so wallets/users that inspect the tree reject it. But the documented client-side mitigation (decode the route, refuse extra auth children) is not enforced on-chain, and users routinely sign aggregator-produced `routeXdr` opaquely. No privileged role, timing, or price manipulation is needed on the attacker's side.

### Recommendation
Enforce on-chain validation at the router: maintain a governance/owner-managed allowlist of venue pool/token addresses (or venue-program hash commitments) and reject payload addresses not on it, so route bytes cannot introduce arbitrary third-party code under the signer's authorization tree. Failing that, require each hop's `pool` to carry a stored venue-registration record. Until then, this remains a signed-auth-tree phishing primitive available to anyone who can supply `swap_xdr` to a victim.

### Proof of Concept
See `tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs`, which pins the mechanism end to end:

- `RogueHopPool::swap` (lines 62-71) runs inside the route and calls `token.transfer(&victim_wallet_token → attacker, amount)` for an unlisted token the victim holds (`WALLET_BALANCE = 77_770_000_000`).
- `UnlistedPoolRouter::execute_strategy` (lines 39-47) takes `hop_pool` from the caller's `swap_xdr`, pays a fair output so `min_out` and measured-delta checks all pass, and still invokes the attacker pool.
- In recording mode the rogue transfer attaches to the caller's `require_auth` entry; in enforcing mode it executes if that tree is signed — matching the threat-model description at `docs/explanation/threat-model.md:154-165`.

Attack flow: attacker serves a quote whose `routeXdr` names `RogueHopPool` as a hop pool → victim submits `execute_strategy(sender=victim, total_in, swap_xdr)` → simulation's auth tree contains the extra `transfer` → victim signs → the swap settles correctly **and** the wallet is drained of the unrelated token.