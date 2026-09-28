### Title
Unvalidated swap routes can execute attacker-controlled contracts that consume the caller’s broader authorization - (File: contracts/controller/src/strategies/swap.rs)

### Summary
The controller passes a caller-supplied swap program directly to the configured aggregator and validates only the controller’s input spend and output receipt. Because route instructions can designate arbitrary venue contracts, a malicious hop can request an unrelated token transfer from the caller while nested inside the authorized strategy call. If the caller signs the authorization tree generated during simulation, the swap can succeed while stealing wallet funds unrelated to the lending position. Severity: High.

### Finding Description
`swap_tokens` loads the configured swap aggregator and invokes `execute_strategy(controller, amount_in, swap)` with the route bytes unchanged. [1](#0-0)  Before that call, the controller authorizes only the intended `token_in` transfer from itself to the router. [2](#0-1) 

After the router returns, the controller checks that it did not gain input or overspend, refunds unused input, and requires a positive measured `token_out` balance increase. [3](#0-2)  Those measurements constrain transfers of controller-held swap assets, but they do not constrain authorization requests made by contracts reached through the route.

The swap program format designates a pool address index for every swap instruction, so a route can name an attacker-controlled contract as a hop. [4](#0-3)  The router’s public ABI decodes and executes the supplied strategy for `sender`. [5](#0-4) 

This is reachable through `swap_collateral`, which authenticates the caller and passes the raw route into `withdraw_and_swap_from_supply`. [6](#0-5)  A nested malicious pool can invoke `token.transfer(victim, attacker, amount)` on an unrelated token. Soroban simulation can record that transfer as a child of the victim’s `swap_collateral` authorization; if the victim signs the complete tree, enforcement accepts it. [7](#0-6) 

### Impact Explanation
An attacker can steal unrelated tokens directly from the victim’s wallet, outside the swapped collateral and beyond the controller’s exact input authorization. [8](#0-7)  The strategy can still deliver a fair-looking output, so the balance-delta and final-risk checks do not prevent the additional wallet transfer. [3](#0-2)  This is theft of user funds with user interaction: the victim must execute the malicious route and sign the poisoned authorization tree. [9](#0-8) 

### Likelihood Explanation
Any unprivileged user can reach `swap_collateral` for an account they own or control, and the route bytes are attacker-supplied rather than constrained by the controller to audited venue addresses. [1](#0-0)  Exploitation requires convincing a victim to sign a transaction whose simulation reveals an extra token-transfer authorization child, which is plausible when wallets or clients display route payloads inadequately. [9](#0-8) 

### Recommendation
Decode the swap program at the controller boundary or expose a router route-manifest API, and reject any venue/pool/token address that is not on a protocol-controlled allowlist. The authorization scope should be limited to the declared swap path, and clients should still reject authorization trees containing any child outside the expected input transfer. [10](#0-9) 

### Proof of Concept
1. Deploy `RoguePool` with storage containing `(victim, unrelated_token, attacker, victim_balance)`.
2. Encode a route whose swap instruction names `RoguePool` as the pool, while arranging a later leg or the router to return a positive amount of the requested output asset.
3. Have the victim call:

   `swap_collateral(victim, victim_account_id, usdc_hub_key, supplied_usdc_amount, eth_hub_key, malicious_route)`

   where `current`, `from_amount`, `new`, and `swap` correspond to the public parameters consumed by `SwapCollateralParams`. [11](#0-10) 
4. During the nested pool call, `RoguePool` invokes `unrelated_token.transfer(victim, attacker, victim_balance)`.
5. Simulation records the transfer beneath the victim’s `swap_collateral` authorization; signing that complete tree makes the malicious transfer enforceable. [7](#0-6) 
6. The strategy still receives positive measured output, so the controller accepts it after the input and output balance checks. [3](#0-2)

### Citations

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

**File:** contracts/swap-aggregator/src/program.rs (L96-103)
```rust
    /// Swap through `venue`: `idx_a` pool, `idx_b` token in, `idx_c` token out.
    Swap(SwapVenue),
    /// Aquarius withdraw: `idx_a` pool, `idx_b` share token, `idx_c` first
    /// index of the per-constituent floor run in `amounts`.
    Burn,
    /// Aquarius deposit: `idx_a` pool, `idx_b` share token, `idx_c` index of
    /// the minimum share count in `amounts`.
    Mint,
```

**File:** contracts/swap-aggregator/src/lib.rs (L245-254)
```rust
    /// Decodes `swap_xdr` as a `StrategyPayload` and runs it for `sender`.
    ///
    /// Requires `sender` authorization. Pulls `total_in` of the input token, runs the
    /// instruction stream, applies fees, checks the minimum output, and returns the amount
    /// delivered to `sender`. Panics with `Error::InvalidRouteXdr` if the XDR does not decode.
    fn execute_strategy(env: Env, sender: Address, total_in: i128, swap_xdr: Bytes) -> i128 {
        renew_instance(&env);
        let payload = StrategyPayload::from_xdr(&env, &swap_xdr)
            .unwrap_or_else(|_| panic_with_error!(&env, Error::InvalidRouteXdr));
        execute::run(env, sender, total_in, payload)
```

**File:** contracts/controller/src/strategies/swap_collateral.rs (L17-24)
```rust
pub(crate) struct SwapCollateralParams<'a> {
    pub account_id: u64,
    pub current: &'a HubAssetKey,
    pub from_amount: i128,
    pub new: &'a HubAssetKey,
    pub swap: &'a StrategySwap,
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
