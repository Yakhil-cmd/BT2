### Title
Unconstrained strategy routes can place attacker-controlled contracts inside the caller's authorization scope and steal unrelated wallet tokens - ([File: contracts/controller/src/strategies/swap.rs])

### Summary
`swap_collateral` accepts caller-supplied route bytes, withdraws the account's collateral into controller custody, and invokes the configured router without restricting which pool contracts the route may invoke or preventing those contracts from requesting additional authorization from the caller. A malicious venue contract can satisfy the measured swap checks while also calling `token.transfer(victim, attacker, amount)`; Soroban simulation records that transfer as a child of the victim's `swap_collateral` authorization, so signing the poisoned authorization tree steals wallet assets unrelated to the lending position. [1](#0-0) [2](#0-1) [3](#0-2) 

### Finding Description
`process_swap_collateral` authorizes `caller`, requires owner or delegate authority over `account_id`, withdraws `from_amount` of `current`, and passes the resulting measured controller balance to `swap_tokens_or_passthrough` with the caller-controlled `swap`. [4](#0-3) [5](#0-4) 

`swap_tokens` treats `swap` only as non-empty opaque bytes, authorizes exactly one controller-to-router input transfer, invokes `router.execute_strategy`, and then validates only the controller's measured input spend and positive output receipt. [6](#0-5) [7](#0-6) [8](#0-7) 

The router's decoded program obtains each hop's `pool`, `token_in`, and `token_out` directly from the payload's address registry and invokes that pool through the selected venue adapter. [3](#0-2) [9](#0-8) [10](#0-9) 

Because the pool address is route-controlled and not bound to an attested venue deployment, an attacker can provide a contract implementing the expected venue ABI while performing an unrelated `from.require_auth()` token transfer from the victim inside the swap call. [11](#0-10) [12](#0-11) [13](#0-12) 

### Impact Explanation
A victim who signs the simulated authorization tree loses arbitrary token balances held in their wallet, including assets never supplied to or listed by the lending protocol. The malicious venue can simultaneously return enough of the expected output token to satisfy the router's measured-output checks and the controller's final account-risk checks, so the theft can coexist with an apparently successful collateral swap. [14](#0-13) [7](#0-6) [15](#0-14) 

This is theft of user funds beyond the submitted collateral amount; neither the route minimum, controller input-measurement, output-measurement, nor solvency check bounds the separate wallet transfer. [7](#0-6) [16](#0-15) 

### Likelihood Explanation
An unprivileged attacker can deploy the malicious pool contract and construct a valid route because hop pool addresses come from caller-controlled route data rather than a protocol-managed pool registry. [17](#0-16) [18](#0-17) [10](#0-9) 

Execution requires the victim to sign an authorization tree containing the malicious child transfer, so the attack relies on malicious route generation, simulation output being accepted without child-authorization inspection, or a compromised route source rather than a signature bypass. [19](#0-18) [20](#0-19) [2](#0-1) 

### Recommendation
Restrict route-selected pool addresses to governance-attested venue deployments before dispatch, and include the venue, pool, input token, and output token in that attestation so an arbitrary contract cannot be reached beneath the caller's lending authorization. [3](#0-2) [9](#0-8) 

Until on-chain attestation exists, clients must simulate the exact transaction, reject any authorization tree containing children other than the expected lending token pulls, and refuse routes whose venue addresses are not known deployments; these client checks should be documented as mandatory rather than optional slippage hygiene. [21](#0-20) [2](#0-1) 

### Proof of Concept
1. A victim owns a lending account with USDC supplied as collateral and also holds an unrelated token `T` in the same wallet. [22](#0-21) [23](#0-22) 
2. The attacker deploys a contract exposing the expected `get_reserves` and `swap` functions for a Soroswap hop, prefunds it with the route's output token, and configures it to call `T.transfer(victim, attacker, balance)` during `swap`. [11](#0-10) [12](#0-11) 
3. The victim calls `swap_collateral(caller, account_id, current, from_amount, new, swap)`, where `current` is the USDC hub asset, `new` is the output hub asset, and `swap` names the attacker's contract as the pool. [24](#0-23) [1](#0-0) 
4. The controller withdraws the measured collateral, authorizes only its own exact controller-to-router input transfer, and executes the route. [25](#0-24) [26](#0-25) [27](#0-26) 
5. The router invokes the attacker's pool; inside that frame, the pool requests the victim's unrelated-token transfer and also sends sufficient output token to the router. [3](#0-2) [28](#0-27) [12](#0-11) 
6. Transaction simulation includes the unrelated `T.transfer(victim, attacker, balance)` as a child authorization under the victim's `swap_collateral` invocation; if the victim signs that tree, the malicious transfer executes while the measured router output lets the strategy continue. [20](#0-19) [19](#0-18) [29](#0-28)

### Citations

**File:** contracts/controller/src/strategies/swap_collateral.rs (L17-30)
```rust
pub(crate) struct SwapCollateralParams<'a> {
    pub account_id: u64,
    pub current: &'a HubAssetKey,
    pub from_amount: i128,
    pub new: &'a HubAssetKey,
    pub swap: &'a StrategySwap,
}

/// Withdraws current collateral, swaps into the new asset, then deposits and
/// checks the account's final risk. Matching assets across hubs pass through.
pub(crate) fn process_swap_collateral(
    env: &Env,
    caller: &Address,
    params: SwapCollateralParams<'_>,
```

**File:** contracts/controller/src/strategies/swap_collateral.rs (L40-50)
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

**File:** contracts/controller/src/strategies/swap_collateral.rs (L67-76)
```rust
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

**File:** contracts/controller/src/strategies/swap.rs (L40-83)
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

/// Passes matching assets through only with an empty route; otherwise swaps.
pub(crate) fn swap_tokens_or_passthrough(
    env: &Env,
    refund_to: &Address,
    token_in: &Address,
    amount_in: i128,
    token_out: &Address,
    swap: &StrategySwap,
) -> i128 {
    if token_in == token_out {
        assert_with_error!(env, swap.is_empty(), GenericError::InvalidPayments);
        amount_in
    } else {
        swap_tokens(env, refund_to, token_in, amount_in, token_out, swap)
    }
}

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

**File:** contracts/swap-aggregator/src/execute/mod.rs (L51-63)
```rust
pub(crate) fn run(env: Env, sender: Address, total_in: i128, payload: StrategyPayload) -> i128 {
    sender.require_auth();

    if total_in <= 0 {
        panic_with_error!(&env, Error::InvalidAmount);
    }

    let StrategyPayload {
        amounts,
        assets,
        ops,
    } = payload;
    let program = Program::decode(&env, &ops, assets.len(), amounts.len());
```

**File:** contracts/swap-aggregator/src/execute/mod.rs (L76-86)
```rust
    // Credit the measured delta, not declared `total_in`: a fee-on-transfer
    // input would otherwise draw the shortfall from the fee reserve.
    let credited_in = transfer_amount_measured(
        &env,
        &input_token,
        &sender,
        &router,
        total_in,
        GenericError::AmountMustBePositive,
    );
    vault.deposit(&input_token, credited_in);
```

**File:** contracts/swap-aggregator/src/execute/mod.rs (L121-135)
```rust
    if !fee_on_input {
        fees::apply_fees_on_token(&env, &mut vault, &output_token, referral_id);
    }

    let total_out = vault.balance_of(&output_token);
    if total_out < total_min_out {
        panic_with_error!(&env, Error::SlippageExceeded);
    }

    vault.withdraw(&output_token, total_out);
    token::Client::new(&env, &output_token).transfer(&router, &sender, &total_out);

    residual::accrue_residual_as_revenue(&env, &mut vault);

    total_out
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

**File:** contracts/controller/src/strategies/legs.rs (L83-108)
```rust
/// Withdraws supply into controller custody and returns its measured receipt.
pub(super) fn withdraw_collateral_to_controller(
    env: &Env,
    account: &mut Account,
    cache: &mut Context,
    req: StrategyWithdraw<'_>,
) -> i128 {
    let controller = env.current_contract_address();
    let balance_before = token::Client::new(env, &req.hub_asset.asset).balance(&controller);

    storage::with_flash_guard(env, || {
        execute_withdrawal(
            env,
            account,
            &controller,
            req.action,
            WithdrawalRequest {
                hub_asset: req.hub_asset,
                amount: req.amount,
                position: req.position,
            },
            cache,
        );
    });

    balance_delta_since(env, &req.hub_asset.asset, &controller, balance_before)
```

**File:** contracts/controller/src/strategies/legs.rs (L231-258)
```rust
/// Withdraws to the controller, then swaps its measured receipt into `token_out`.
/// Matching assets pass through unchanged; returns the available output.
pub(crate) fn withdraw_and_swap_from_supply(
    env: &Env,
    account: &mut Account,
    cache: &mut Context,
    caller: &Address,
    from: &HubAssetKey,
    amount: i128,
    token_out: &Address,
    swap: &StrategySwap,
    action: events::PositionAction,
) -> i128 {
    let supply_pos = get_supply_position_or_panic(env, account, from);

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
```

**File:** common/src/token.rs (L33-51)
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
```

**File:** contracts/swap-aggregator/src/types.rs (L21-45)
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
}
```

**File:** contracts/swap-aggregator/src/program.rs (L281-292)
```rust
            if idx_a >= assets_len || idx_b >= assets_len {
                panic_with_error!(env, Error::InvalidRouteXdr);
            }
            match opcode {
                Opcode::Swap(_) => {
                    if idx_c >= assets_len {
                        panic_with_error!(env, Error::InvalidRouteXdr);
                    }
                    if idx_b == idx_c {
                        panic_with_error!(env, Error::SameToken);
                    }
                }
```

**File:** contracts/swap-aggregator/src/venues/soroswap.rs (L51-59)
```rust
pub(crate) fn swap(ctx: &HopContext<'_>) {
    let token_in_is_0 = ctx.hop.token_in < ctx.hop.token_out;

    let no_args: Vec<Val> = vec![ctx.env];
    let (reserve_0, reserve_1): (i128, i128) = ctx.env.invoke_contract(
        &ctx.hop.pool,
        &Symbol::new(ctx.env, "get_reserves"),
        no_args,
    );
```

**File:** contracts/swap-aggregator/src/venues/soroswap.rs (L71-87)
```rust
    let token_client = token::Client::new(ctx.env, &ctx.hop.token_in);
    token_client.transfer(ctx.router, &ctx.hop.pool, &ctx.amount_in);

    let (amount_0_out, amount_1_out) = if token_in_is_0 {
        (0_i128, requested_out)
    } else {
        (requested_out, 0_i128)
    };
    let args: Vec<Val> = vec![
        ctx.env,
        amount_0_out.into_val(ctx.env),
        amount_1_out.into_val(ctx.env),
        ctx.router.into_val(ctx.env),
    ];
    let _: () = ctx
        .env
        .invoke_contract(&ctx.hop.pool, &symbol_short!("swap"), args);
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

**File:** contracts/swap-aggregator/src/venues/mod.rs (L42-58)
```rust
    let received = ctx
        .output_balance()
        .checked_sub(before_out)
        .unwrap_or_else(|| panic_with_error!(env, Error::ZeroOutput));
    if received <= 0 {
        panic_with_error!(env, Error::ZeroOutput);
    }

    let after_in = ctx.input_balance();
    let spent = before_in
        .checked_sub(after_in)
        .unwrap_or_else(|| panic_with_error!(env, Error::InvalidAmount));
    if spent != amount_in {
        panic_with_error!(env, Error::InvalidAmount);
    }

    received
```
