### Title
Unvalidated swap routes can disguise wallet-draining transfers inside a signed strategy authorization - (File: contracts/controller/src/strategies/swap.rs)

### Summary
`swap_collateral`, `swap_debt`, `multiply`, and `repay_debt_with_collateral` accept caller-controlled opaque `swap` bytes and forward them to the configured aggregator without inspecting the venues or contract addresses encoded in the route. The router decodes and executes the supplied program, while hop dispatch trusts the payload-selected `pool` address. Consequently, a malicious route can place attacker-controlled code beneath the caller’s authorization tree and add an unrelated token transfer from the victim to the attacker. If a wallet or user signs the simulated authorization tree without detecting that extra child invocation, the transaction settles normally while draining unrelated wallet funds.

### Finding Description
`swap_collateral(caller, account_id, current, amount, new, swap)` authorizes the caller, validates account ownership, withdraws collateral, and passes `swap` into `swap_tokens_or_passthrough`. [1](#0-0)  The shared swap helper only checks that the bytes are non-empty, obtains the configured router, authorizes one exact `token_in` transfer from the controller to the router, and invokes `router.execute_strategy(controller, amount_in, swap)`. [2](#0-1) 

The controller does not decode `swap`, enumerate its hops, or restrict the pool/venue addresses it names; `StrategySwap` is simply `Bytes`. [3](#0-2)  On the router side, `execute_strategy` requires `sender` authorization, decodes the supplied `StrategyPayload`, and executes the encoded instruction stream. [4](#0-3)  Hop dispatch selects a venue adapter from the payload and each adapter operates on the payload’s `hop.pool`; the router authorizes that pool to pull the hop input, establishing that the pool address is route-controlled rather than allowlisted by this dispatch layer. [5](#0-4) [6](#0-5) 

A malicious pool can therefore execute attacker-chosen code while the strategy remains below the victim’s root authorization. During simulation, an additional `token.transfer(victim, attacker, amount)` performed by that code is represented as another child invocation for the victim. Signing that tree authorizes both the expected strategy and the unrelated wallet transfer. The controller’s balance-delta checks bound only the controller-held swap input and output; they do not inspect or constrain other children that route-selected code adds to the caller’s authorization tree. [7](#0-6) 

### Impact Explanation
This enables theft of user funds beyond the collateral amount intentionally committed to the strategy. The stolen asset need not be either `current.asset` or `new.asset`, because the malicious nested contract can target another token held by the victim. The transaction can still produce positive measured swap output and pass the controller’s final account-risk checks, so the lending operation appears successful. The root cause is analogous to domain spoofing: the victim approves what is presented as a normal strategy authorization, while a crafted route embeds an additional transfer authority.

### Likelihood Explanation
An unprivileged attacker can deploy the malicious venue contract and construct the poisoned route without privileged access. Exploitation requires victim interaction: the victim must submit a route supplied by the attacker and sign an authorization tree containing the additional transfer. Wallets or integrations that display only the root controller call—or that do not clearly render nested token transfers—make this practical. The affected controller paths are ordinary permissionless owner/delegate strategy calls, including `multiply`, `swap_debt`, `swap_collateral`, and `repay_debt_with_collateral`. [8](#0-7) 

### Recommendation
Do not treat route bytes as opaque trusted input. Enforce a governance-approved venue/pool allowlist at the router boundary or otherwise constrain routes so venue execution cannot invoke arbitrary contracts under the sender’s authorization tree. Clients should also decode the full route, display every nested invocation produced by simulation, and reject any strategy authorization tree containing children beyond the exact expected input transfer. The controller-side checks should be complemented by an explicit invariant that route execution cannot add unrelated `require_auth` invocations for the account owner.

### Proof of Concept
1. Deploy a malicious contract exposing the interface expected by one router venue and configure it to transfer `VICTIM_TOKEN` from the victim to the attacker when invoked.
2. Construct `swap` bytes whose route passes through that contract as `hop.pool`, while arranging a small positive output in the expected `new.asset`.
3. Induce the victim to call:

   `swap_collateral(victim, account_id, current, amount, new, poisoned_swap)`

   where `victim` owns or delegates `account_id`, `current` is an existing collateral position, `amount > 0`, and `new` is a valid distinct collateral market.
4. Simulate the transaction. The expected path withdraws `amount` of `current`, forwards `poisoned_swap` to `execute_strategy`, and invokes the malicious pool.
5. The malicious pool calls `VICTIM_TOKEN.transfer(victim, attacker, wallet_balance)`. Simulation records that call as an additional child beneath the victim’s `swap_collateral` authorization.
6. If the victim signs that simulated tree, the malicious transfer executes, the router returns enough `new.asset` to satisfy `received > 0`, the controller redeposits the output, and final strategy risk checks can pass. The victim loses unrelated wallet funds in the same transaction.

### Citations

**File:** contracts/controller/src/strategies/swap_collateral.rs (L40-63)
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
```

**File:** contracts/controller/src/strategies/swap.rs (L21-55)
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
```

**File:** common/src/types/shared.rs (L9-10)
```rust
/// Encoded swap route passed to the aggregator router's `execute_strategy` entry point.
pub type StrategySwap = Bytes;
```

**File:** contracts/swap-aggregator/src/execute/mod.rs (L51-64)
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

**File:** contracts/swap-aggregator/src/venues/mod.rs (L34-40)
```rust
    match hop.venue {
        SwapVenue::Soroswap => soroswap::swap(&ctx),
        SwapVenue::Aquarius => aquarius::swap(&ctx, tokens_cache),
        SwapVenue::Phoenix => phoenix::swap(&ctx),
        SwapVenue::Sushi => sushi::swap(&ctx),
        SwapVenue::CometDex => comet::swap(&ctx),
    };
```

**File:** contracts/swap-aggregator/src/venues/mod.rs (L87-95)
```rust
    /// Authorizes the pool to pull `amount_in` of `token_in` from the router.
    pub fn authorize_pool_pull(&self) {
        authorize_token_transfer(
            self.env,
            &self.hop.token_in,
            self.router,
            &self.hop.pool,
            self.amount_in,
        );
```

**File:** contracts/controller/src/lib.rs (L225-291)
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
        strategies::multiply::process_multiply(
            &env,
            &caller,
            MultiplyParams {
                account_id,
                spoke_id,
                collateral: &collateral,
                debt_to_flash_loan,
                debt: &debt,
                mode,
                swap: &swap,
                initial_payment,
                convert_swap,
            },
        )
    }

    /// Borrows `amount` of `new_debt`, converts it to `existing_debt` via `swap`
    /// and repays with the proceeds. Requires owner or delegate authorization.
    #[when_not_paused]
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
