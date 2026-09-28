### Title
Unverified swap-route `pool` address executes arbitrary contract code beneath the caller's authorization tree, draining the caller's wallet - (File: contracts/swap-aggregator/src/venues/mod.rs)

### Summary
The llama-stack report class — unverified parameters reaching a code-execution sink — maps directly onto the swap route bytes accepted by controller strategy entrypoints. A route's per-hop `pool` address and `token_in`/`token_out` come entirely from caller-supplied `swap_xdr`; neither the controller nor the router keeps an allowlist of venues or pools, so any deployed contract is invoked mid-swap. Because the venue call sits below the user's `require_auth`, arbitrary code in the named "pool" can append a `token.transfer(victim, attacker, …)` that an honest simulation records as a child of the victim's own authorization entry — and it executes whenever the victim signs the simulated tree.

### Finding Description
`controller::swap_collateral`, `swap_debt`, `multiply`, and `repay_debt_with_collateral` forward caller-supplied `route` bytes to the configured swap-aggregator. The router dispatches each hop by calling `env.invoke_contract(&hop.pool, "swap", …)` (and equivalent venue functions) on the pool address embedded in the payload, verified only by measured input/output balance deltas, not by identity [1](#0-0) . The threat model confirms the router "calls the pool and token addresses its payload names and keeps no allowlist of them, so a route can put third-party code on the call stack below the caller's authorization" [2](#0-1) .

The harness test `rogue_hop_pool_transfer_joins_caller_auth_tree` proves the chain end-to-end: a `RogueHopPool.swap` that performs `token::Client::transfer(&victim, &attacker, &amount)` on an unrelated wallet token is recorded by simulation as a child invocation of Alice's `swap_collateral` auth entry, and when Alice signs that recorded tree the transfer executes — her entire `WALLET_BALANCE` moves to the attacker while the swap itself settles "fairly" [3](#0-2) . The enforcing-mode test shows the host rejects the rogue transfer only when the signed tree omits it — i.e., the sole defense is client-side tree inspection, which no on-chain component enforces [4](#0-3) .

### Impact Explanation
Theft of user funds: any token in the victim's wallet (not just the routed amount) can be transferred to the attacker in the same transaction. Neither `total_min_out` nor the post-swap solvency check bounds the loss, because the stolen transfer is orthogonal to the measured swap legs — the swap pays out normally while the wallet is emptied [5](#0-4) .

### Likelihood Explanation
An unprivileged attacker deploys a malicious pool contract, embeds it in a crafted `swap_xdr`, and serves it to a victim through any quote/route channel. The victim's standard workflow — simulate, sign the recorded auth tree, submit — produces exactly the poisoned tree the host will accept; wallets and SDKs that auto-sign simulation output do so without flagging the extra child. All in-scope preconditions (own malicious contract as the venue, victim's own entrypoint call) are permissionless. Rated Medium rather than High because exploitation requires the victim to sign a tree containing the extra child invocation, and the threat model already directs clients to reject unexpected children.

### Recommendation
Bind route execution to verified counterparties on-chain: have the controller (or router) maintain a governance-approved allowlist of venue/pool addresses, or restrict `invoke_contract` targets to pools registered per hub asset. Alternatively, authorize the input pull with a scoped allowance rather than a `transfer` rooted under the user's auth, and reject any route whose execution would record child invocations under `sender.require_auth` beyond the single input transfer — e.g., by performing the venue call from a context that cannot inherit the caller's auth.

### Proof of Concept
Provided by `tests/test-harness/tests/controller/../strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs`: `UnlistedPoolRouter`/`RogueHopPool` fixtures show `simulation_records_the_rogue_pool_wallet_transfer_under_the_callers_swap_collateral_entry` — Alice's wallet token balance goes from `WALLET_BALANCE` to 0 and the attacker's to `WALLET_BALANCE`, while her collateral swap completes normally [6](#0-5) .

### Citations

**File:** contracts/swap-aggregator/src/venues/mod.rs (L23-56)
```rust
pub(crate) fn dispatch_hop(
    env: &Env,
    router: &Address,
    hop: &SwapHop,
    amount_in: i128,
    tokens_cache: &mut Map<Address, Vec<Address>>,
) -> i128 {
    let ctx = HopContext::new(env, router, hop, amount_in);
    let before_in = ctx.input_balance();
    let before_out = ctx.output_balance();

    match hop.venue {
        SwapVenue::Soroswap => soroswap::swap(&ctx),
        SwapVenue::Aquarius => aquarius::swap(&ctx, tokens_cache),
        SwapVenue::Phoenix => phoenix::swap(&ctx),
        SwapVenue::Sushi => sushi::swap(&ctx),
        SwapVenue::CometDex => comet::swap(&ctx),
    };

    let received = ctx
        .output_balance()
        .checked_sub(before_out)
        .unwrap_or_else(|| panic_with_error!(env, Error::ZeroOutput));
    if received <= 0 {
        panic_with_error!(env, Error::ZeroOutput);
    }

    let after_in = ctx.input_balance();
    let spent = before_in
        .checked_sub(after_in)
        .unwrap_or_else(|| panic_with_error!(env, Error::InvalidAmount));
    if spent != amount_in {
        panic_with_error!(env, Error::InvalidAmount);
    }
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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L194-227)
```rust
#[test]
fn simulation_records_the_rogue_pool_wallet_transfer_under_the_callers_swap_collateral_entry() {
    let s = Scene::new();
    let route = s.route_through_pool_stealing(WALLET_BALANCE);

    // `simulateTransaction` runs recording mode with non-root auth disabled.
    s.t.env.mock_all_auths();
    s.try_swap(&route)
        .expect("recording mode accepts the route");
    let recorded = s.t.env.auths();
    std::println!("recorded auth tree = {recorded:#?}");

    let stolen_transfer = AuthorizedInvocation {
        function: AuthorizedFunction::Contract((
            s.wallet_token.clone(),
            symbol_short!("transfer"),
            (s.alice.clone(), s.attacker.clone(), WALLET_BALANCE).into_val(&s.t.env),
        )),
        sub_invocations: std::vec![],
    };
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
}
```

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L258-269)
```rust
    // Same route, with the tree that simulation returned.
    let stolen_transfer = MockAuthInvoke {
        contract: &s.wallet_token,
        fn_name: "transfer",
        args: (s.alice.clone(), s.attacker.clone(), WALLET_BALANCE).into_val(&s.t.env),
        sub_invokes: &[],
    };
    s.try_swap_with_signed_tree(&rogue, core::slice::from_ref(&stolen_transfer))
        .expect("the poisoned tree authorizes the rogue transfer");
    assert_eq!(s.wallet(&s.alice), 0);
    assert_eq!(s.wallet(&s.attacker), WALLET_BALANCE);
}
```
