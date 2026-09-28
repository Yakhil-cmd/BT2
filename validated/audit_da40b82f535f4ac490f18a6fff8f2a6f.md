### Title
Direct token transfers to the pool or controller are permanently stranded - (File: contracts/pool/src/lib.rs)

### Summary
XOXNO Lending treats direct token transfers as unbooked donations and provides no public or controller-mediated recovery path for the excess balance. The pool credits only measured amounts received through controller flows, while every state-changing pool entrypoint is restricted to the controller, and the controller exposes no generic token-rescue function. As a result, an unprivileged user who transfers a supported or unsupported token directly to the pool or controller permanently loses access to those tokens. [1](#0-0) [2](#0-1) 

### Finding Description
The controller’s `supply` path measures only the balance increase caused by the caller’s authorized transfer and submits that measured amount to the pool. [3](#0-2)  The pool then credits exactly that supplied amount to the market’s accounting `cash` book and mints the corresponding supply shares. [4](#0-3) 

A direct `token.transfer(user, pool, amount)` therefore increases the token balance but not any market’s `cash`, supply shares, revenue shares, or a user position. Outbound token movement is performed only through `Cache::transfer_out`, which merely sends a caller-specified amount and does not provide a way to reconcile or claim excess balances. [5](#0-4)  The complete public pool mutation surface contains supply, borrow, withdraw, repay, recapitalize, flash-loan, strategy, liquidation, revenue, market, and upgrade functions, but no arbitrary-token rescue or sweep entrypoint. [2](#0-1) 

The same issue applies to tokens sent directly to the controller. Controller refunds deliberately return only the positive balance delta measured during an operation and preserve any pre-existing controller balance. [6](#0-5) 

### Impact Explanation
Directly transferred tokens become permanently inaccessible to the sender. For a listed asset, the pool’s physical token balance can exceed all booked claims, but no entrypoint maps that excess back to the depositor. For an unlisted asset held by the pool or controller, there is not even market accounting capable of selecting the token for withdrawal. This causes permanent freezing of user funds. [7](#0-6) [8](#0-7) 

### Likelihood Explanation
Any unprivileged token holder can trigger this state with one ordinary token transfer to the pool or controller address. No privileged action, oracle manipulation, market condition, or attacker capability is required. The loss depends on a mistaken or incorrectly integrated direct transfer, so it is less likely than a flaw in the normal supply flow, but the resulting freeze is deterministic once the transfer occurs. [9](#0-8) 

### Recommendation
Implement a bounded recovery mechanism for unbooked balances. For example, add a controller-administered rescue path that can transfer only `token.balance(pool) - total_booked_cash_for_asset` for listed assets, and arbitrary balances for assets with no market. Alternatively, reject integration patterns that send tokens directly and clearly expose a permissionless claim for unbooked donations.

### Proof of Concept
1. Let `pool = Controller::get_pool_address()` and let `asset` be any token address. [10](#0-9) 
2. An unprivileged user calls the token contract’s `transfer(user, pool, amount)`.
3. Query the token balance and the relevant market reserves. The token balance includes `amount`, while `get_reserves` remains unchanged because no controller flow credited cash. [11](#0-10) 
4. Calling `Controller::supply` afterward cannot reclaim the prior balance because it measures only the new transfer delta. [12](#0-11) 
5. `Controller::withdraw` cannot reclaim it because it requires and burns an existing supply position rather than paying unbooked balances. [13](#0-12) 
6. No pool or controller entrypoint can return the donation, so `amount` remains stranded. [2](#0-1)

### Citations

**File:** contracts/pool/src/lib.rs (L33-36)
```rust
//! - Every mutator requires the owner through `#[only_owner]`; views are public.
//! - Cash is an accounting book, separate from the token balance. A flash loan
//!   checks the token balance after payout, after the callback and after
//!   repayment.
```

**File:** contracts/pool/src/lib.rs (L128-193)
```rust
    /// Accrues, mints scaled supply shares and credits cash per entry. The
    /// controller transfers the tokens in before this call. Owner-only.
    #[only_owner]
    fn supply(env: Env, entries: Vec<PoolSupplyEntry>) -> Vec<PoolPositionMutation> {
        ops::run_batch(&env, entries, ops::supply::apply)
    }

    /// Batch-borrows assets and transfers them to `receiver`: accrues
    /// interest, mints scaled debt, debits cash, and enforces max
    /// utilization after each mint. Restricted to the owner; returns one
    /// [`PoolPositionMutation`] per entry.
    #[only_owner]
    fn borrow(
        env: Env,
        receiver: Address,
        entries: Vec<PoolBorrowEntry>,
    ) -> Vec<PoolPositionMutation> {
        ops::run_batch(&env, entries, |env, entry| {
            ops::borrow::apply(env, &receiver, entry)
        })
    }

    /// Burns supply shares and transfers the underlying to `receiver`.
    /// `is_liquidation` skips the max-utilization check and may withhold a
    /// protocol fee. Owner-only; `actual_amount` is gross of that fee.
    #[only_owner]
    fn withdraw(
        env: Env,
        receiver: Address,
        is_liquidation: bool,
        entries: Vec<PoolWithdrawEntry>,
    ) -> Vec<PoolPositionMutation> {
        ops::run_batch(&env, entries, |env, entry| {
            ops::withdraw::apply(env, &receiver, is_liquidation, entry)
        })
    }

    /// Burns scaled debt up to the repay amount, credits cash with the net
    /// repay and refunds overpayment to `payer`. Owner-only.
    #[only_owner]
    fn repay(env: Env, payer: Address, actions: Vec<PoolAction>) -> Vec<PoolPositionMutation> {
        ops::run_batch(&env, actions, |env, action| {
            ops::repay::apply(env, &payer, action)
        })
    }

    /// Accrues interest for each market in `hub_assets` through the current
    /// ledger time. Commits state even with no elapsed time to reserve the write
    /// footprint, and emits its market state event. Restricted to the owner.
    #[only_owner]
    fn update_indexes(env: Env, hub_assets: Vec<HubAssetKey>) {
        ops::market::accrue(&env, hub_assets);
    }

    /// Credits cash up to the market's backing shortfall
    /// (`guards::backing_shortfall`) and transfers the excess back to `payer`.
    /// The controller transfers `amount` in before this call. Restricted to
    /// the owner; returns a [`PoolAmountMutation`] with the amount applied.
    #[only_owner]
    fn recapitalize(
        env: Env,
        hub_asset: HubAssetKey,
        payer: Address,
        amount: i128,
    ) -> PoolAmountMutation {
        ops::recapitalize::apply(&env, hub_asset, payer, amount)
```

**File:** interfaces/pool/src/lib.rs (L14-66)
```rust
    fn create_market(env: Env, hub_id: u32, params: MarketParamsRaw);

    fn update_params(env: Env, hub_asset: HubAssetKey, model: InterestRateModel);

    fn update_indexes(env: Env, hub_assets: Vec<HubAssetKey>);

    fn supply(env: Env, entries: Vec<PoolSupplyEntry>) -> Vec<PoolPositionMutation>;

    fn borrow(
        env: Env,
        receiver: Address,
        entries: Vec<PoolBorrowEntry>,
    ) -> Vec<PoolPositionMutation>;

    fn withdraw(
        env: Env,
        receiver: Address,
        is_liquidation: bool,
        entries: Vec<PoolWithdrawEntry>,
    ) -> Vec<PoolPositionMutation>;

    fn repay(env: Env, payer: Address, actions: Vec<PoolAction>) -> Vec<PoolPositionMutation>;

    fn net_settle(env: Env, entry: PoolNetSettleEntry) -> PoolNetSettleResult;

    fn seize_positions(env: Env, entries: Vec<PoolSeizeEntry>);

    fn flash_loan(
        env: Env,
        hub_asset: HubAssetKey,
        initiator: Address,
        receiver: Address,
        amount: i128,
        data: Bytes,
    ) -> i128;

    fn create_strategy(
        env: Env,
        receiver: Address,
        action: PoolAction,
        charge_fee: bool,
    ) -> PoolStrategyMutation;

    fn recapitalize(
        env: Env,
        hub_asset: HubAssetKey,
        payer: Address,
        amount: i128,
    ) -> PoolAmountMutation;

    fn claim_revenue(env: Env, hub_asset: HubAssetKey) -> PoolAmountMutation;

    fn upgrade(env: Env, new_wasm_hash: BytesN<32>);
```

**File:** contracts/controller/src/positions/supply.rs (L114-129)
```rust
    let pool_addr = cache.cached_pool_address();
    let mut entries: Vec<PoolSupplyEntry> = Vec::new(env);
    for (hub_asset, amount_in) in aggregated.iter() {
        let asset_config: AssetConfig = cache.require_spoke_asset(account.spoke_id, &hub_asset);
        let received = payments::transfer_amount_measured(
            env,
            &hub_asset.asset,
            caller,
            &pool_addr,
            amount_in,
            GenericError::AmountMustBePositive,
        );
        let position = account.get_or_create_supply_position(&hub_asset, &asset_config);
        entries.push_back(PoolSupplyEntry {
            action: make_pool_action(&position, received, hub_asset.clone()),
        });
```

**File:** contracts/controller/src/positions/supply.rs (L180-198)
```rust
    let mut entries: Vec<PoolWithdrawEntry> = Vec::new(env);
    for (hub_asset, amount) in aggregated.iter() {
        enforce_spoke_asset_flags(
            env,
            cache,
            account.spoke_id,
            &hub_asset,
            FreezePolicy::AllowOnExit,
        );
        let position = get_supply_position_or_panic(env, account, &hub_asset);
        let requested = if amount == 0 {
            WITHDRAW_ALL_SENTINEL
        } else {
            amount
        };
        entries.push_back(PoolWithdrawEntry {
            action: make_pool_action(&position, requested, hub_asset.clone()),
            protocol_fee: 0,
        });
```

**File:** contracts/pool/src/ops/supply.rs (L23-40)
```rust
    let (mut cache, mut position) = ops::load_leg(env, &entry.action);
    let amount = entry.action.amount;

    guards::require_backed_market(env, &cache);

    let minted = cache.calculate_scaled_supply(amount);
    assert_with_error!(
        env,
        amount == 0 || minted.raw() > 0,
        GenericError::SupplyRoundsToZeroShares
    );

    position = position.checked_add(env, minted);
    cache.mint_supply(minted);

    cache.credit_cash(amount);

    let snapshot = cache.commit();
```

**File:** contracts/pool/src/cache/cash.rs (L43-53)
```rust
    /// Transfers `amount` of the market asset from the pool to `recipient`.
    ///
    /// Rejects negative amounts; zero is a no-op. Does not adjust accounting cash.
    pub(crate) fn transfer_out(&self, recipient: &Address, amount: i128) {
        require_nonneg_amount(&self.env, amount);
        if amount == 0 {
            return;
        }
        let tok = token::Client::new(&self.env, &self.params.asset_id);
        tok.transfer(&self.env.current_contract_address(), recipient, &amount);
    }
```

**File:** contracts/controller/src/payments.rs (L39-51)
```rust
/// Refunds only the controller balance increase since `balance_before`,
/// preserving the pre-existing balance; no-op for a nonpositive delta.
pub(crate) fn refund_controller_balance_delta(
    env: &Env,
    asset: &Address,
    balance_before: i128,
    refund_to: &Address,
) {
    let controller = env.current_contract_address();
    let excess = balance_delta_since(env, asset, &controller, balance_before);
    if excess > 0 {
        token::Client::new(env, asset).transfer(&controller, refund_to, &excess);
    }
```

**File:** contracts/controller/src/lib.rs (L390-395)
```rust
    /// Covers a pool backing shortfall using measured receipts from `payer`.
    /// Refunds excess and returns the amount applied in asset units.
    /// Permissionless; requires payer authorization.
    fn recapitalize(env: Env, payer: Address, hub_asset: HubAssetKey, amount: i128) -> i128 {
        markets::recapitalize(&env, payer, hub_asset, amount)
    }
```

**File:** contracts/controller/src/lib.rs (L489-492)
```rust
    /// Returns the deployed liquidity pool address.
    fn get_pool_address(env: Env) -> Address {
        storage::get_pool(&env)
    }
```

**File:** common/src/token.rs (L16-31)
```rust
pub fn transfer_amount_measured(
    env: &Env,
    asset: &Address,
    from: &Address,
    to: &Address,
    amount: i128,
    non_positive_error: GenericError,
) -> i128 {
    assert_with_error!(env, amount > 0, non_positive_error);
    let tok = token::Client::new(env, asset);
    let pre = tok.balance(to);
    tok.transfer(from, to, &amount);
    let post = tok.balance(to);
    post.checked_sub(pre)
        .unwrap_or_else(|| panic_with_error!(env, GenericError::AmountMustBePositive))
}
```
