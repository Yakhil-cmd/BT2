### Title
Caller-supplied swap routes can smuggle unauthorized token transfers into the caller’s authorization tree - (File: contracts/controller/src/strategies/swap.rs)

### Summary
High. `multiply`, `swap_debt`, `swap_collateral`, and `repay_debt_with_collateral` accept opaque route bytes and forward them to the configured swap router without the controller decoding or constraining the contracts reached by that route. [1](#0-0) [2](#0-1)  A malicious route can therefore execute a contract that requests an unrelated `token.transfer(caller, attacker, amount)` beneath the caller-authorized controller invocation; simulation records that transfer as an additional authorization child, and enforcement executes it if the caller signs the poisoned tree. [3](#0-2) [4](#0-3) 

### Finding Description
`StrategySwap` is an opaque `Bytes` payload supplied by the caller. [1](#0-0)  The controller passes it unchanged to `SwapAggregatorClient::execute_strategy`; its validation is limited to a nonempty payload, an exact controller input-transfer authorization, measured controller input/output balances, positive output, and subsequent account risk checks. [5](#0-4) [6](#0-5) 

Those checks protect only the routed input and expected output. They do not identify or reject a third-party contract embedded in the route that makes an unrelated token transfer from the caller. The repository’s threat model explicitly notes that route-selected pool and token addresses are not allowlisted and that such a transfer is attached to the caller’s signed authorization tree. [3](#0-2) 

An unprivileged user can reach this through `multiply(caller, account_id, spoke_id, collateral, debt_to_flash_loan, debt, mode, swap, initial_payment, convert_swap)`, where both `swap` and `convert_swap` are caller-controlled route payloads. [7](#0-6) [8](#0-7)  The same primitive is reachable through `swap_debt`, which forwards its caller-controlled `swap` to `swap_tokens_or_passthrough`. [9](#0-8) [10](#0-9) 

### Impact Explanation
A malicious route can steal unrelated wallet tokens from the account owner or delegate that signs the transaction. The attacker can return enough expected output for the strategy to satisfy the controller’s positive-output, repayment, collateralization, and final-risk checks while the route’s nested contract separately transfers another token from the victim to the attacker. [6](#0-5) [11](#0-10) 

This is theft of user funds outside the bounded routed amount. The poisoned child authorization must appear in the signed authorization tree, but ordinary wallet or frontend flow may present the operation as a lending swap without making the extra token transfer sufficiently understandable. [12](#0-11) 

### Likelihood Explanation
Likelihood is Medium. Constructing the malicious route requires no protocol privilege, compromised key, leaked secret, upgrade, or special parameter. The attacker needs a victim to submit a crafted route and sign an authorization tree containing the extra token transfer; a route-generation service, malicious interface, or copied payload can provide that transaction. Honest simulation exposes the child transfer, so exploitation depends on incomplete client-side route decoding or authorization inspection rather than silent execution. [4](#0-3) [12](#0-11) 

### Recommendation
Replace opaque route bytes with a decoded, bounded strategy representation in the controller-facing authorization domain, or require the router to execute only governance-allowlisted venue adapters and pool contracts. The authorization policy should bind each route to explicitly declared token contracts, venue contracts, function selectors, and permitted balance movements so a hop cannot request an unrelated caller transfer. Until an on-chain allowlist exists, clients and route builders must decode the complete route, simulate the transaction, and reject every authorization tree containing children other than the expected input transfer. [2](#0-1) [3](#0-2) 

### Proof of Concept
1. Victim owns an unrelated wallet token not listed as a lending asset.
2. Attacker deploys a route-compatible pool contract whose `swap` function calls `token.transfer(victim, attacker, wallet_balance)`.
3. Attacker supplies a `multiply` transaction whose `swap` bytes route through that contract while returning enough configured collateral for the account’s final solvency checks to pass.
4. Simulation records the unrelated wallet-token transfer as a child under the victim’s `multiply` authorization; the repository’s test demonstrates this exact auth-tree attachment and resulting balance movement. [4](#0-3) 
5. If the victim signs that tree, enforcement performs the unrelated transfer while the lending operation still completes; the same test shows the transfer succeeds when the poisoned child is signed and fails when it is omitted. [13](#0-12)

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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L195-268)
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

#[test]
fn enforced_auth_moves_the_wallet_token_only_when_the_signed_tree_lists_the_rogue_transfer() {
    let s = Scene::new();

    // Control: a pool that touches nothing passes with the honest root-only tree.
    let benign = s.route_through_pool_stealing(0);
    s.try_swap_with_signed_tree(&benign, &[])
        .expect("the honest tree authorizes an honest route");
    assert_eq!(s.wallet(&s.alice), WALLET_BALANCE);

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

**File:** contracts/controller/src/strategies/multiply.rs (L86-97)
```rust
    let swap_amount_in = amount_received
        .checked_add(debt_extra)
        .unwrap_or_else(|| panic_with_error!(env, GenericError::MathOverflow));

    let swapped_collateral = swap_tokens_or_passthrough(
        env,
        caller,
        &debt.asset,
        swap_amount_in,
        &collateral.asset,
        swap,
    );
```

**File:** contracts/controller/src/strategies/swap_debt.rs (L18-24)
```rust
pub(crate) struct SwapDebtParams<'a> {
    pub account_id: u64,
    pub existing_debt: &'a HubAssetKey,
    pub new_debt_amount: i128,
    pub new_debt: &'a HubAssetKey,
    pub swap: &'a StrategySwap,
}
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
