### Title
Attacker-controlled route bytes inject arbitrary contract calls under the caller's authorization tree, draining wallet funds beyond the routed amount - ([File: contracts/controller/src/strategies/swap.rs](contracts/controller/src/strategies/swap.rs))

### Summary
The GitLab CVE is a command-injection class: attacker-controlled configuration data (`DOCKER_AUTH_CONFIG`) is passed into a privileged execution context and runs as arbitrary commands. The analog in XOXNO Lending is the caller-controlled `swap: Bytes` route in `multiply`, `swap_debt`, `swap_collateral`, and `repay_debt_with_collateral`. The controller forwards these opaque bytes to `router.execute_strategy` inside a call tree rooted at the caller's `require_auth`, and neither the controller nor the router allowlists the pool/token addresses the payload names. A route can therefore name an attacker-deployed "pool" that issues `token.transfer(victim, attacker, amount)`; that call joins the victim's recorded authorization tree and executes once the victim signs, stealing arbitrary wallet tokens unrelated to the swap.

### Finding Description
`swap_tokens` in `contracts/controller/src/strategies/swap.rs:34-38` grants the router exactly one input-token transfer authorization and then invokes `router.execute_strategy(&controller, &amount_in, swap)`, where `swap` is the raw caller-supplied payload. Callers reach it through `process_swap_debt` (`swap_debt.rs:65-72`), `swap_collateral`, `multiply`, and `repay_debt_with_collateral` — all gated only by `require_authorized_caller`/`require_owner_or_delegate`, i.e. unprivileged.

The controller's post-conditions only measure the controller's own `token_in`/`token_out` balance deltas (`swap.rs:40-54`). They do not constrain which contracts the route invokes. The project's own threat model states the router "keeps no allowlist" of pool/token addresses, "a route can put third-party code on the call stack below the caller's authorization," and a token transfer such code makes from the caller "executes if the caller signs that tree. The loss is then the caller's wallet, not the routed amount" (`docs/explanation/threat-model.md:154-165`).

The harness test `tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs` proves this concretely: `RogueHopPool::swap` calls `token::Client::transfer(victim, attacker, amount)` (lines 62-71), the route names it as the hop pool (lines 111-125), simulation records the wallet-draining transfer as a child of Alice's `swap_collateral` auth entry, and after execution `wallet(alice) == 0` while `wallet(attacker) == WALLET_BALANCE` (lines 195-227).

### Impact Explanation
Theft of user funds. Any token in the victim's wallet — not just the swap input — can be transferred to the attacker through the injected call, because Soroban authorization trees authorize every descendant invocation once the root is signed. The controller's measured-output checks and post-swap risk gates all still pass (`verify_router_output` only requires `received > 0`), so a fairly-priced route carries the payload unnoticed.

### Likelihood Explanation
The exploit needs the victim to submit an attacker-crafted route and sign the resulting auth tree. This is realistic: routes are produced by an off-chain quote service and embedded opaquely as `routeXdr` (the SDK docs instruct clients never to construct payloads on-chain), and the standard `simulateTransaction` flow records the poisoned child automatically — a wallet that signs what simulation returns authorizes the theft. No privileged role, upgrade, or leaked key is required; the attacker only needs to get one crafted `swap` payload in front of a swapping user.

### Recommendation
Constrain what route payloads may invoke. Options: (a) the router enforces an on-chain allowlist of venue/pool contracts (or venue adapters pin the pool address derived from registered venue registries rather than taking it from the payload); (b) the controller requires the router to isolate hops so that no hop contract can issue `require_auth`-bearing calls attributable to the caller — e.g. the router performing hops from its own address with its own auth, never under the caller's tree; (c) at minimum, the controller/SDK should expose a decoded-view helper so clients can reject any authorization tree containing children other than the single input transfer. The residual client-side rule currently documented in the threat model is the only defense today.

### Proof of Concept
Already present in-repo: `tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs`.

1. Register `UnlistedPoolRouter` as the swap aggregator and `RogueHopPool` with plan `(alice, wallet_token, attacker, WALLET_BALANCE)`.
2. Build `RoutedSwap{hop_pool: rogue_pool, min_out: FAIR_OUT_ETH, token_in: USDC, token_out: ETH}` and encode as `swap` bytes.
3. Alice calls `Controller::swap_collateral(alice, account_id, USDC_hub_key, SWAP_IN_USDC, ETH_hub_key, route)`.
4. Inside the call, the controller authorizes one USDC transfer to the router (`swap.rs:34`) and invokes `execute_strategy`; the router calls `RogueHopPool::swap`, which calls `wallet_token.transfer(alice, attacker, WALLET_BALANCE)`.
5. Simulation records that transfer as a child of Alice's `swap_collateral` root auth (test assertion at lines 206-222). Once Alice signs the recorded tree, the swap settles correctly (Alice's ETH supply = `FAIR_OUT_ETH`) and her entire `wallet_token` balance sits with the attacker (lines 224-226).