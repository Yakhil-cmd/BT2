### Title
Unlisted tokens sent to `LiquidityPool` are permanently locked - (File: `contracts/pool/src/lib.rs`)

### Summary
The pool can custody arbitrary Stellar assets through direct token transfers, but its interface contains no generic recovery path for a token outside a configured market.

### Finding Description
`LiquidityPool` receives tokens at its contract address independently of its market accounting. Every outbound transfer goes through `Cache::transfer_out`, which always uses the market's configured `params.asset_id`, so no operation can transfer a different token held by the pool [1](#0-0) . The public interface exposes only market operations such as `supply`, `borrow`, `withdraw`, `repay`, `flash_loan`, `recapitalize`, and `claim_revenue`; all are keyed to an existing `HubAssetKey` market and none accepts an arbitrary token and recipient [2](#0-1) . Mutating pool functions are additionally restricted to the owner, normally the controller [3](#0-2) .

The controller likewise has no general token-recovery entrypoint. Its balance-delta refund helper deliberately preserves the pre-existing controller balance and returns only a positive increase measured during the operation [4](#0-3) . Consequently, an unrelated token already sitting at the controller cannot be extracted through the flash-position refund path either; `refund_assets` is limited to assets listed for the relevant spoke and hub [5](#0-4) .

### Impact Explanation
Any unlisted airdropped, misdirected, or donated token transferred directly to the pool is permanently frozen. No unprivileged path, and no pool owner path other than replacing the contract code, can move that token because outbound custody is hard-bound to the market asset.

### Likelihood Explanation
Any address can send an arbitrary supported Stellar token directly to the pool contract. Token distributions, mistaken transfers, and unsolicited incentives do not require a pool market to exist, making the condition externally reachable.

### Recommendation
Add an owner/governance-controlled rescue entrypoint to the pool that transfers only balances exceeding accounted obligations. Prefer an API such as `sweep(token, recipient, amount)` that rejects configured market assets unless the amount is above the pool's cash backing, and allows unrestricted recovery of unlisted tokens.

### Proof of Concept
1. Deploy `LiquidityPool` and configure a market for asset `A`.
2. From any user address, call token `T.transfer(user, pool, amount)`, where `T` is not a configured market asset.
3. Observe `T.balance(pool) == amount`.
4. Attempt every available pool operation: each either requires a market for `T` or transfers only `params.asset_id`.
5. The `amount` of token `T` remains locked at the pool indefinitely.

### Citations

**File:** contracts/pool/src/cache/cash.rs (L46-52)
```rust
    pub(crate) fn transfer_out(&self, recipient: &Address, amount: i128) {
        require_nonneg_amount(&self.env, amount);
        if amount == 0 {
            return;
        }
        let tok = token::Client::new(&self.env, &self.params.asset_id);
        tok.transfer(&self.env.current_contract_address(), recipient, &amount);
```

**File:** interfaces/pool/src/lib.rs (L20-65)
```rust
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

```

**File:** contracts/pool/src/lib.rs (L91-96)
```rust
    /// Sets `admin` as the Ownable owner at construction. Every
    /// `#[only_owner]` entrypoint afterward requires that owner, normally the
    /// controller, to authorize.
    pub fn __constructor(env: Env, admin: Address) {
        ownable::set_owner(&env, &admin);
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

**File:** contracts/controller/src/strategies/flash_position.rs (L217-255)
```rust
fn validate_refund_assets(
    env: &Env,
    cache: &mut Context,
    spoke_id: u32,
    hub_id: u32,
    collaterals: &Vec<(HubAssetKey, i128)>,
    refund_assets: &Vec<Address>,
) {
    let limits = storage::get_position_limits(env);
    assert_with_error!(
        env,
        refund_assets.len() <= limits.max_supply_positions,
        GenericError::InvalidPayments
    );

    let mut seen: Map<Address, bool> = Map::new(env);
    for asset in refund_assets.iter() {
        assert_with_error!(
            env,
            !seen.contains_key(asset.clone()),
            GenericError::InvalidPayments
        );
        seen.set(asset.clone(), true);
        // Refund transfers run after the guard; restrict tokens to listed assets.
        cache.require_listed_active_config(
            spoke_id,
            &HubAssetKey {
                hub_id,
                asset: asset.clone(),
            },
        );
        for (collateral, _) in collaterals.iter() {
            assert_with_error!(
                env,
                asset != collateral.asset,
                GenericError::InvalidPayments
            );
        }
    }
```
