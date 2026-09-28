### Title
User-controlled swap routes can inject malicious contract calls into the caller’s authorization tree - (File: `contracts/controller/src/strategies/swap.rs`)

### Summary
`multiply`, `swap_debt`, `swap_collateral`, and `repay_debt_with_collateral` accept caller-supplied opaque `swap` bytes and forward them to the configured router. The controller constrains its own input-token transfer, but not the contracts reached while the router interprets the route. A malicious route can therefore place an attacker-controlled venue beneath the caller’s authorized strategy call and make that venue request additional caller-signed token transfers.

### Finding Description
`swap_collateral` authenticates `caller`, verifies account ownership, and passes the user-provided `swap` into `withdraw_and_swap_from_supply`. [1](#0-0)  `swap_debt` follows the same pattern after borrowing the replacement debt into controller custody. [2](#0-1)  `multiply` and `repay_debt_with_collateral` expose the same route-controlled execution path. [3](#0-2) [4](#0-3) 

`swap_tokens` rejects only empty routes, passes the opaque bytes to `SwapAggregatorClient::execute_strategy`, and then checks only the controller’s input and output balances. [5](#0-4)  The explicit authorization created by the controller covers only `token_in.transfer(controller, router, amount_in)` and contains no sub-invocations, so it does not constrain caller-authenticated operations requested by code reached inside the route. [6](#0-5)  Post-route checks detect overspending or zero output for the controller, but they do not undo an unrelated caller-wallet transfer that execution successfully included in the caller’s authorization tree. [7](#0-6) 

### Impact Explanation
A route can execute attacker-controlled code while the caller’s strategy authorization is active, add a request such as `victim_token.transfer(victim, attacker, victim_balance)` to that authorization tree, and drain any token the victim signs for. The strategy can still return a legitimate positive output and pass the controller’s balance and account-risk checks, so protocol-level settlement checks do not bound the unrelated wallet loss. [8](#0-7)  This is theft of user funds and qualifies as High severity.

### Likelihood Explanation
The vulnerable parameters are reachable through normal user-facing strategy entrypoints, with `swap` exposed directly as bytes in `multiply`, `swap_debt`, `swap_collateral`, and `repay_debt_with_collateral`. [9](#0-8) [10](#0-9) [11](#0-10) [12](#0-11)  Exploitation requires convincing a user to submit a malicious route and sign the resulting expanded authorization tree; no privileged role, leaked key, upgrade, or protocol insolvency precondition is needed. Likelihood is Medium rather than High because an enforcing wallet can reject the unexpected child authorization.

### Recommendation
Do not allow arbitrary route-selected code to execute beneath the caller’s strategy authorization. Constrain executable venue or pool addresses to a protocol-governed allowlist before calling the router, or replace opaque route programs with an explicitly decoded and validated route structure containing only approved venue identities. Clients should also decode the complete authorization tree and reject any child call other than the expected strategy funding transfer, but that is defense-in-depth rather than a protocol fix.

### Proof of Concept
1. Deploy a malicious venue contract whose swap function returns a valid output to the router but also calls `token::transfer(victim, attacker, victim_balance)` on a token held by the victim.
2. Construct route bytes that include that venue while preserving positive measured output.
3. Have the victim invoke `swap_collateral(caller=victim, account_id, current, amount, new, swap=malicious_route)`; the controller authenticates the call and forwards `malicious_route` to `execute_strategy`. [13](#0-12) 
4. Transaction simulation records the malicious wallet transfer as a child beneath the victim’s `swap_collateral` authorization.
5. If the victim signs that tree, the malicious venue transfers the unrelated wallet token to the attacker while the route returns enough `new` collateral for `NoSwapOutput` and final risk checks to pass. [7](#0-6)

### Citations

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

**File:** contracts/controller/src/strategies/swap_debt.rs (L55-72)
```rust
    let amount_received = borrow_into_controller(
        env,
        &mut account,
        new_debt,
        new_debt_amount,
        true,
        PositionAction::SwDebtR,
        &mut cache,
    );

    let repay_amount = swap_tokens_or_passthrough(
        env,
        caller,
        &new_debt.asset,
        amount_received,
        &existing_debt.asset,
        swap,
    );
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

**File:** contracts/controller/src/strategies/repay_debt_with_collateral.rs (L108-117)
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

**File:** contracts/controller/src/lib.rs (L225-236)
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
```

**File:** contracts/controller/src/lib.rs (L258-265)
```rust
    fn swap_debt(
        env: Env,
        caller: Address,
        account_id: u64,
        existing_debt: HubAssetKey,
        amount: i128,
        new_debt: HubAssetKey,
        swap: Bytes,
```

**File:** contracts/controller/src/lib.rs (L283-290)
```rust
    fn swap_collateral(
        env: Env,
        caller: Address,
        account_id: u64,
        current: HubAssetKey,
        amount: i128,
        new: HubAssetKey,
        swap: Bytes,
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
