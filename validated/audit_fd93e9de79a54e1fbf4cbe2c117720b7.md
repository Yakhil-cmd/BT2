### Title
Unbounded swap-route callbacks can execute token transfers under the caller’s signed authorization tree - (File: contracts/controller/src/strategies/swap.rs)

### Summary
`swap_collateral`, `swap_debt`, `repay_debt_with_collateral`, and `multiply` accept opaque route bytes and pass them to the configured router. The router interprets those bytes as a list of token and pool contract addresses, without requiring those addresses to be governance-approved. A crafted route can therefore invoke attacker-deployed contract code during the victim’s controller call. If that code requests a token transfer from the victim, Soroban simulation records it as a child of the victim’s `swap_collateral` authorization. A wallet or integration that signs the returned tree without rejecting unexpected children authorizes the theft, while the controller’s balance-delta and final-risk checks still pass.

### Finding Description
The controller exposes attacker-controlled `swap: Bytes` arguments on `swap_debt` and `swap_collateral`; `repay_debt_with_collateral` uses the same pattern. [1](#0-0) [2](#0-1) 

For `swap_collateral`, the controller authenticates the caller and verifies that it owns or delegates the target account, but it does not decode or constrain the contents of `swap`. [3](#0-2)  It then forwards those bytes through `withdraw_and_swap_from_supply`. [4](#0-3) 

The common swap implementation only requires non-empty bytes, obtains the configured router, grants that router one exact input transfer, and invokes `execute_strategy` with the opaque payload. [5](#0-4)  Its subsequent checks bound only the routed input and require a positive output balance; they do not inspect external contract calls reached by the route or reject an expanded caller authorization tree. [6](#0-5) 

The route payload names pool and token addresses in an address registry, and the venue dispatcher invokes the selected adapter for the named pool. [7](#0-6)  For example, the Aquarius adapter invokes `get_tokens` and `swap` on the payload-supplied `pool` address. [8](#0-7)  No production allowlist prevents that address from identifying attacker-deployed Wasm code.

The repository’s authorization test demonstrates the resulting behavior: a rogue pool called below `swap_collateral` executes `token.transfer(victim, attacker, amount)`, simulation records that transfer as a child of the victim’s controller authorization, and the wallet balance moves when that tree is signed. [9](#0-8) [10](#0-9) 

### Impact Explanation
This can permanently steal tokens held directly by the victim’s wallet, including tokens unrelated to the lending position and not included in the routed input. The victim can receive a fair-looking swap output and pass all account-risk checks while the malicious pool performs the separately signed wallet transfer.

The demonstrated sequence results in the victim’s unrelated wallet token balance becoming zero and the attacker receiving the full amount. [11](#0-10)  This is theft of user funds, not merely an unfavorable swap or route-quality issue.

### Likelihood Explanation
An unprivileged attacker can deploy a Wasm pool-shaped contract, generate a valid route naming it, and deliver that route through a quote, dapp integration, delegated strategy interface, or copied transaction payload. The controller path is reachable through the normal `swap_collateral` entrypoint and its `swap` argument. [12](#0-11) 

Exploitation requires the victim to sign an authorization tree containing an extra transfer invocation. That is a real UI-required precondition, but it matches the report’s bug class: a crafted input reaches attacker-controlled code and relies on the product/integration mishandling that input. Since an honest `swap_collateral` root normally has no child invocation while the malicious simulation introduces one, clients that mechanically sign simulation output are exposed. [13](#0-12) 

### Recommendation
Do not treat `swap` as inert data. Enforce a governance-controlled allowlist or registry of venue pool addresses before execution, ideally in the router’s decoded route rather than in opaque bytes. At minimum, decode `StrategyPayload` in the controller or router, extract every `assets[idx_a]` pool used by swap/burn/mint instructions, and reject any pool not explicitly approved for the declared venue.

Separately, prevent malicious route code from extending the user’s authorization: wallets and integrations should simulate the complete transaction, decode the route, and reject any authorization child beyond the exact expected token pull for the chosen operation. The expected child set should be derived from the operation, not copied blindly from simulation output.

### Proof of Concept
1. Attacker deploys `RoguePool`, exposing an ABI compatible with the selected venue’s `swap` call.
2. `RoguePool.swap()` calls `token.transfer(victim, attacker, victim_wallet_balance)` for a token unrelated to the swap.
3. Attacker constructs a valid `StrategyPayload` whose `assets` registry includes:
   - `token_in = USDC`,
   - `token_out = ETH`,
   - `pool = RoguePool`.
4. Victim calls:

```text
swap_collateral(
  caller = victim,
  account_id = victim_account,
  current = HubAssetKey { hub_id: 1, asset: USDC },
  amount = 50_000_000_000,
  new = HubAssetKey { hub_id: 1, asset: ETH },
  swap = malicious_payload
)
```

5. The controller authorizes the router’s exact USDC pull and invokes `execute_strategy(controller, amount, malicious_payload)`. [14](#0-13) 
6. The router dispatches to the payload-selected `RoguePool`; during that call, the pool requests the unrelated wallet-token transfer.
7. Simulation records the malicious `transfer(victim, attacker, amount)` beneath the victim’s `swap_collateral` authorization. [15](#0-14) 
8. If the victim signs that simulation-produced tree, the transaction completes, the attacker receives the unrelated wallet tokens, and the victim’s account can still receive a positive ETH deposit and pass the final strategy checks. [11](#0-10)

### Citations

**File:** contracts/controller/src/lib.rs (L258-291)
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
```

**File:** contracts/controller/src/lib.rs (L311-319)
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

**File:** contracts/controller/src/strategies/swap_collateral.rs (L55-64)
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

**File:** contracts/swap-aggregator/src/venues/mod.rs (L23-40)
```rust
pub(crate) fn dispatch_hop(
    env: &Env,
    router: &Address,
    hop: &SwapHop,
    amount_in: i128,
    tokens_cache: &mut Map<Address, Vec<Address>>,
) -> i128 {
    let ctx = HopContext::new(env, router, hop, amount_in);
    let before_in = ctx.input_balance();
    let before_out = ctx.output_balance();

    match hop.venue {
        SwapVenue::Soroswap => soroswap::swap(&ctx),
        SwapVenue::Aquarius => aquarius::swap(&ctx, tokens_cache),
        SwapVenue::Phoenix => phoenix::swap(&ctx),
        SwapVenue::Sushi => sushi::swap(&ctx),
        SwapVenue::CometDex => comet::swap(&ctx),
    };
```

**File:** contracts/swap-aggregator/src/venues/aquarius/pool.rs (L16-35)
```rust
pub(super) fn invoke_pool_swap(
    env: &Env,
    router: &Address,
    pool: &Address,
    token_in: &Address,
    in_idx: u32,
    out_idx: u32,
    amount_in: i128,
) {
    authorize_token_transfer(env, token_in, router, pool, amount_in);
    let args: Vec<Val> = vec![
        env,
        router.into_val(env),
        in_idx.into_val(env),
        out_idx.into_val(env),
        to_u128(env, amount_in).into_val(env),
        0_u128.into_val(env),
    ];
    let _: u128 = env.invoke_contract(pool, &symbol_short!("swap"), args);
}
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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L195-226)
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
```

**File:** docs/explanation/threat-model.md (L154-165)
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
user.
```
