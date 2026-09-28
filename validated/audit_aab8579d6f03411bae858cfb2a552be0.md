### Title
Attacker-controlled swap routes can append unauthorized token transfers to the caller’s signed authorization tree - ([File: `contracts/controller/src/strategies/swap.rs`])

### Summary
The controller treats `swap` as opaque attacker-controlled route data and invokes the configured router without identifying the contracts that route can reach. [1](#0-0) [2](#0-1)  The router resolves pool addresses from the payload’s unrestricted address registry and invokes them as venue contracts. [3](#0-2) [4](#0-3)  A malicious hop can therefore execute arbitrary contract code below the caller’s `require_auth` and request an unrelated wallet-token transfer that simulation attaches as a signed child authorization. [5](#0-4) [6](#0-5) 

### Finding Description
`swap_collateral` accepts a caller-selected `swap: Bytes` argument and only checks that the caller owns or delegates the lending account. [1](#0-0) [7](#0-6)  The controller then authorizes one input transfer to the configured router, invokes `execute_strategy`, and validates only the controller’s input spend and positive output receipt. [8](#0-7) [9](#0-8) 

The router payload names each hop’s `pool`, `token_in`, and `token_out` through its `assets` registry; the program validator checks registry bounds but does not restrict a pool address to an approved venue deployment. [10](#0-9) [4](#0-3)  The venue adapters then issue contract calls to that payload-selected pool, such as `get_reserves` and `swap` for Soroswap. [11](#0-10) [12](#0-11) 

This is the on-chain analogue of SSRF: the caller chooses the destination, but protocol execution carries the request inside an authorization context the user signs. [13](#0-12)  Because nested third-party code can ask for `caller` authorization, simulation records such a transfer as a child of the caller’s controller authorization rather than as an unrelated authorization request. [14](#0-13)  The controller’s `RouterOverspend`, output, and final-risk checks cover the routed collateral amount only; they do not inspect or bound a child transfer from the caller’s wallet. [9](#0-8) [15](#0-14) 

### Impact Explanation
A victim who signs the poisoned authorization tree can lose any wallet token selected by the malicious hop, including assets that were never supplied to XOXNO Lending. [14](#0-13)  The attacker can simultaneously make the hop pay the expected output token, allowing `verify_router_output` and the account’s final risk checks to pass while the unrelated wallet transfer executes. [16](#0-15) [15](#0-14)  This is theft of user funds, not merely a bad exchange rate or route-quality failure. [17](#0-16) 

### Likelihood Explanation
No privileged role, oracle manipulation, leaked key, upgrade, or protocol balance is required to construct the malicious pool and route payload. [18](#0-17) [19](#0-18)  Execution does require the victim to submit or sign a transaction containing the malicious route and the resulting child authorization. [5](#0-4) [20](#0-19)  That prerequisite limits exploitability compared with a fully self-contained contract bug, but ordinary quote composition and simulation can hide the extra child invocation unless the client explicitly inspects the complete authorization tree. [21](#0-20) 

### Recommendation
Restrict strategy execution to governance-allowlisted venue/pool contract addresses, or otherwise authenticate each hop destination before invoking it. [22](#0-21)  The allowlist must cover every contract that a route can place on the call stack; checking only token addresses is insufficient because the malicious destination is the hop contract itself. [10](#0-9)  Until destination allowlisting exists, wallets and quote services should reject any strategy authorization tree containing calls beyond the expected protocol/router input-transfer shape, but this client-side check does not remove the contract-level exposure. [21](#0-20) 

### Proof of Concept
1. Deploy a malicious contract implementing the selected venue’s expected methods, including `get_reserves` and `swap`. [11](#0-10) [12](#0-11) 
2. Fund that contract with enough `token_out` to pay a positive measured output. [23](#0-22) 
3. In its `swap` method, transfer the quoted `token_out` amount to the router and also invoke `unrelated_token.transfer(victim, attacker, balance)`. [12](#0-11) [6](#0-5) 
4. Construct a `swap` payload whose `assets` registry contains the malicious pool, listed input token, listed output token, and unrelated wallet token as needed by the malicious code. [24](#0-23) [4](#0-3) 
5. Have the victim call `swap_collateral(victim, account_id, current=USDC, amount, new=ETH, swap=malicious_payload)`. [1](#0-0) 
6. Transaction simulation records the malicious wallet transfer as a child under the victim’s `swap_collateral` authorization; if the victim signs that returned tree, the unrelated token is transferred to the attacker while the strategy output and account checks still succeed. [9](#0-8) [20](#0-19)

### Citations

**File:** contracts/controller/src/lib.rs (L283-291)
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

**File:** contracts/swap-aggregator/src/execute/mod.rs (L51-67)
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

    let input_token = assets.get_unchecked(program.token_in);
    let output_token = assets.get_unchecked(program.token_out);
    let total_min_out = amounts.get_unchecked(program.min_out);
```

**File:** contracts/swap-aggregator/src/execute/mod.rs (L152-166)
```rust
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

**File:** contracts/swap-aggregator/src/program.rs (L210-218)
```rust
        let token_in = buf[head::TOKEN_IN] as u32;
        let token_out = buf[head::TOKEN_OUT] as u32;
        let min_out = buf[head::MIN_OUT] as u32;
        if token_in >= assets_len || token_out >= assets_len || min_out >= amounts_len {
            panic_with_error!(env, Error::InvalidRouteXdr);
        }
        if token_in == token_out {
            panic_with_error!(env, Error::SameToken);
        }
```

**File:** contracts/swap-aggregator/src/program.rs (L281-287)
```rust
            if idx_a >= assets_len || idx_b >= assets_len {
                panic_with_error!(env, Error::InvalidRouteXdr);
            }
            match opcode {
                Opcode::Swap(_) => {
                    if idx_c >= assets_len {
                        panic_with_error!(env, Error::InvalidRouteXdr);
```

**File:** contracts/controller/src/risk/validation.rs (L12-16)
```rust
/// Authenticates `caller` and rejects execution during a flash loan.
pub(crate) fn require_authorized_caller(env: &Env, caller: &Address) {
    caller.require_auth();
    require_not_flash_loaning(env);
}
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

**File:** contracts/controller/src/strategies/swap_collateral.rs (L40-48)
```rust
    require_authorized_caller(env, caller);

    assert_with_error!(env, current != new, GenericError::AssetsAreTheSame);
    config::require_hub_active(env, current.hub_id);
    require_positive_amount(env, from_amount);

    let mut account = storage::get_account(env, account_id);
    account::require_owner_or_delegate(env, account_id, caller, &account.owner);
    let mut cache = Context::new(env);
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

**File:** contracts/swap-aggregator/src/venues/soroswap.rs (L54-58)
```rust
    let no_args: Vec<Val> = vec![ctx.env];
    let (reserve_0, reserve_1): (i128, i128) = ctx.env.invoke_contract(
        &ctx.hop.pool,
        &Symbol::new(ctx.env, "get_reserves"),
        no_args,
```

**File:** contracts/swap-aggregator/src/venues/soroswap.rs (L85-87)
```rust
    let _: () = ctx
        .env
        .invoke_contract(&ctx.hop.pool, &symbol_short!("swap"), args);
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
