The report's bug class — attacker-supplied content reaching an execution path without validation — maps to caller-controlled swap routes. Let me check the controller-side handling.### Title
Unvalidated swap-route `pool` addresses execute attacker code under the caller's authorization tree, draining wallet funds beyond the routed amount - ([File: contracts/controller/src/strategies/swap.rs](contracts/controller/src/strategies/swap.rs))

### Summary
The MoinMoin bug class is "unrestricted upload reaches an execution path": user-supplied content is invoked as code without an allowlist. The analog in XOXNO Lending is the caller-supplied `swap` route (`StrategySwap` XDR) accepted verbatim by `multiply`, `swap_collateral`, `swap_debt`, `repay_debt_with_collateral`, and `flash_position`. The controller forwards it to the configured router, which invokes whichever `pool`/`token` contract addresses the payload names — no venue or pool allowlist exists anywhere on-chain. An attacker who gets a victim to sign a poisoned route runs arbitrary contract code on the call stack **below the victim's authorization entry**, so token transfers that code performs from the victim are recorded as children of the victim's `swap_collateral` auth and execute against the victim's whole wallet, not just the routed amount.

### Finding Description
`swap_tokens` decodes nothing from `swap`: it only requires non-empty bytes, authorizes one `token_in.transfer(controller → router, amount_in)`, and calls `router.execute_strategy(controller, amount_in, swap)` inside the flash guard [1](#0-0) . The post-checks bound only the *controller's* balances: input must not grow, spend must not exceed `amount_in`, and measured `token_out` receipt must be positive [2](#0-1) . Nothing constrains what other contract code runs during the router call.

The router dispatches hops to `hop.pool` / `hop.token_in` / `hop.token_out` addresses taken from the payload registry with no allowlist [3](#0-2) . The threat model states this explicitly: "The router calls the pool and token addresses its payload names and keeps no allowlist of them, so a route can put third-party code on the call stack below the caller's authorization… The loss is then the caller's wallet, not the routed amount, and neither the payload minimum nor the final risk gate bounds it" [4](#0-3) .

The harness test proves the mechanics: a `RogueHopPool` named by the route calls `token.transfer(victim → attacker, WALLET_BALANCE)` during `swap_collateral`, the stolen transfer is recorded as a sub-invocation of the victim's signed `swap_collateral` auth entry, and the call succeeds — victim wallet balance goes to zero while the position still receives the fair swap output [5](#0-4) [6](#0-5) .

### Impact Explanation
Theft of user funds. The victim loses arbitrary tokens held in their wallet — any Stellar asset the rogue "pool" contract chooses to transfer — completely unbounded by the swap amount, the route's `min_out`, or the controller's post-swap risk gates. The swap itself can settle perfectly (fair output deposited into the victim's position), so nothing in the transaction signals the theft. This scales to every token in the victim's account for which the signed auth tree is accepted.

### Likelihood Explanation
Reachable by a single unprivileged address: any caller of `swap_collateral`/`multiply`/`swap_debt`/`repay_debt_with_collateral` supplies the route bytes. The exploitation vector is a poisoned route served to the victim (malicious or compromised quote server, phishing dapp) — exactly the "attacker uploads content that later executes" shape of CVE-2012-6081. The only mitigation is off-chain: the client must decode `routeXdr` and refuse auth trees with unexpected child invocations [7](#0-6) , which every integrating wallet/SDK must independently implement correctly. A user who signs a simulated envelope without inspecting children is drained. The protocol's own accounting is never violated, so on-chain monitoring sees a fully "successful" strategy call.

### Recommendation
Enforce the trust boundary on-chain rather than in every client:

- Maintain a governance-managed allowlist of venue pool/share-token addresses in the router (or a venue registry contract), and have `dispatch_hop` reject any `hop.pool` not on it.
- At minimum, have the controller restrict the `token_in`/`token_out` registry entries to listed market assets it already knows, so payload token addresses cannot name arbitrary victim-held contracts for the theft leg.
- Emit an event listing every external contract address invoked per strategy call so wallet-side verification is a checklist rather than full XDR decoding.
- Document at the SDK level that signers must reject any auth tree under `swap_collateral`/`multiply`/etc. containing children other than the single `token_in.transfer` — the harness test shows exactly the shape to reject [8](#0-7) .

### Proof of Concept
Covered by `tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs`:

1. Deploy `RogueHopPool` configured with `(victim = Alice, wallet_token, to = attacker, amount = WALLET_BALANCE)`; its `swap()` executes `token::Client::transfer(alice, attacker, WALLET_BALANCE)` [5](#0-4) .
2. Build a `RoutedSwap` whose `hop_pool` is that contract, with a fair `min_out` so the swap settles [9](#0-8) .
3. Alice calls `controller.swap_collateral(alice, account_id, USDC, SWAP_IN_USDC, ETH, route)` and signs the simulated auth tree.
4. Result: recorded auth tree contains the stolen `wallet_token.transfer(alice → attacker, WALLET_BALANCE)` as a sub-invocation of Alice's `swap_collateral` entry; Alice's wallet token balance is `0`, attacker holds `WALLET_BALANCE`, and Alice's position still shows `FAIR_OUT_ETH` supply [6](#0-5) .

No controller check fails: `RouterOverspend`, `NoSwapOutput`, and the final health-factor gates all pass because the theft touches neither `token_in` nor `token_out` — the rogue pool spends a third token directly from the signer's wallet.

### Citations

**File:** contracts/controller/src/strategies/swap.rs (L33-38)
```rust
    // Authorize only this token transfer to this router for this exact amount.
    authorize_transfer_as_current(env, token_in, &controller, &router_addr, amount_in);

    storage::with_flash_guard(env, || {
        let _ = router.execute_strategy(&controller, &amount_in, swap);
    });
```

**File:** contracts/controller/src/strategies/swap.rs (L41-54)
```rust
    let in_after = token_in_client.balance(&controller);
    assert_with_error!(env, in_after <= in_before, StrategyError::RouterOverspend);
    let actual_spent = in_before - in_after;
    assert_with_error!(
        env,
        actual_spent <= amount_in,
        StrategyError::RouterOverspend
    );
    let leftover = amount_in - actual_spent;
    if leftover > 0 {
        token_in_client.transfer(&controller, refund_to, &leftover);
    }

    verify_router_output(env, token_out, out_before)
```

**File:** contracts/swap-aggregator/src/venues/mod.rs (L34-40)
```rust
    match hop.venue {
        SwapVenue::Soroswap => soroswap::swap(&ctx),
        SwapVenue::Aquarius => aquarius::swap(&ctx, tokens_cache),
        SwapVenue::Phoenix => phoenix::swap(&ctx),
        SwapVenue::Sushi => sushi::swap(&ctx),
        SwapVenue::CometDex => comet::swap(&ctx),
    };
```

**File:** docs/explanation/threat-model.md (L154-165)
```markdown
That bound covers the controller's own grant only. The router calls the pool
and token addresses its payload names and keeps no allowlist of them, so a
route can put third-party code on the call stack below the caller's
authorization. A token transfer that such code makes from the caller is
recorded by an honest simulation as a child of the caller's authorization
entry, and it executes if the caller signs that tree. The loss is then the
caller's wallet, not the routed amount, and neither the payload minimum nor the
final risk gate bounds it. An honest swap strategy gives the caller no child
entry, and a direct router swap gives exactly one input transfer. A client must
decode the route it signs and refuse an authorization tree with any other
child. The direct `execute_strategy` path has the same exposure for every swap
user.
```

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L62-72)
```rust
    pub fn swap(env: Env) {
        let (victim, wallet_token, to, amount): (Address, Address, Address, i128) = env
            .storage()
            .instance()
            .get(&symbol_short!("PLAN"))
            .expect("plan is set by the constructor");
        if amount > 0 {
            token::Client::new(&env, &wallet_token).transfer(&victim, &to, &amount);
        }
    }
}
```

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L111-125)
```rust
    fn route_through_pool_stealing(&self, amount: i128) -> Bytes {
        let plan = (
            self.alice.clone(),
            self.wallet_token.clone(),
            self.attacker.clone(),
            amount,
        );
        RoutedSwap {
            hop_pool: self.t.env.register(RogueHopPool, plan),
            min_out: FAIR_OUT_ETH,
            token_in: self.t.resolve_asset("USDC"),
            token_out: self.t.resolve_asset("ETH"),
        }
        .to_xdr(&self.t.env)
    }
```

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L172-183)
```rust
        let root = MockAuthInvoke {
            contract: &self.t.controller,
            fn_name: "swap_collateral",
            args: self.swap_args(route),
            sub_invokes: children,
        };
        self.t.env.mock_auths(&[MockAuth {
            address: &self.alice,
            invoke: &root,
        }]);
        self.try_swap(route)
    }
```

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L214-226)
```rust
    let poisoned_root = AuthorizedInvocation {
        function: AuthorizedFunction::Contract((
            s.t.controller.clone(),
            Symbol::new(&s.t.env, "swap_collateral"),
            s.swap_args(&route),
        )),
        sub_invocations: std::vec![stolen_transfer],
    };
    assert_eq!(recorded, std::vec![(s.alice.clone(), poisoned_root)]);

    assert_eq!(s.wallet(&s.alice), 0);
    assert_eq!(s.wallet(&s.attacker), WALLET_BALANCE);
    assert_eq!(s.t.supply_balance_raw(ALICE, "ETH"), FAIR_OUT_ETH);
```

**File:** skills/xoxno-swap-aggregator/payload.md (L154-164)
```markdown
## Verify `routeXdr` before signing

`verifyRouteBytes` works for standalone and composed quotes; it does not require a
`transaction`. `verifyStandaloneEnvelope` adds envelope checks. `verifyRoutePayload`
combines both for the standalone signing path. The envelope's actual
`InvokeContractArgs.contract_address` is authoritative; `transaction.routerContract`
is untrusted response metadata and is intentionally unused. Copy this snippet into an
application module such as `verify-route-payload.ts`; the other examples import that
module.

```ts
```
