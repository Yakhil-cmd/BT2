### Title
Scaled-balance `i128` overflow during mandatory accrual permanently freezes market funds - (File: common/src/rates/simulate.rs)

### Summary
**Severity: Medium.** A sufficiently large market can reach a state where converting scaled supply or debt to its indexed RAY value exceeds `i128::MAX`, causing every subsequent operation that touches the market to panic during mandatory interest accrual. [1](#0-0) [2](#0-1) 

### Finding Description
Supply and borrow positions are stored as scaled RAY shares, with `calculate_scaled_borrow` deriving debt shares from the token amount and current borrow index. [3](#0-2) 

Each market action loads its position through `load_leg`, which calls `synced_market` and therefore runs `interest::global_sync` before performing the requested operation. [4](#0-3) [5](#0-4) 

`accrue_step` first unscales both aggregate debt and aggregate supply through `scaled_to_original`. [1](#0-0) [6](#0-5) 

That conversion computes `scaled * index / RAY` through `Ray::mul` and `mul_div_half_up`. [7](#0-6) 

The intermediate product is safely widened to `I256`, but `to_i128()` returns `None` when the resulting value cannot fit into `i128`, which `mul_div_half_up` converts into a `MathOverflow` panic. [8](#0-7) [9](#0-8) 

`update_borrow_index` caps the index itself, but it does not bound the separate `borrowed * borrow_index / RAY` or `supplied * supply_index / RAY` products used for market valuation. [10](#0-9) 

`global_sync` marks the market accrued only after all chunks have completed, so a panic rolls back the accrual and leaves `last_timestamp` behind current time. [11](#0-10) 

Because elapsed time only increases afterward, every later attempt reaches the same overflowing multiplication before repayment, withdrawal, liquidation, settlement, recapitalization, or index maintenance can execute. [12](#0-11) [5](#0-4) 

### Impact Explanation
Once the indexed value of aggregate debt or supply crosses the `i128` boundary, user funds in that market are permanently frozen absent a contract upgrade or other privileged recovery. [1](#0-0) [11](#0-10) 

The public `repay`, `withdraw`, and `liquidate` controller entrypoints cannot bypass the failure because their pool legs synchronize the market before burning shares or moving cash. [13](#0-12) [14](#0-13) [15](#0-14) 

This leaves suppliers unable to exit, borrowers unable to repay, liquidators unable to process the account, and the market unable to continue normal operation even though the token balance may remain in the pool. [16](#0-15) [4](#0-3) 

### Likelihood Explanation
Exploitation requires no privileged role: the attacker can create an account with `supply` and then draw liquidity with `borrow`, subject to the market’s configured caps, available token balances, collateral value, and solvency rules. [17](#0-16) [18](#0-17) 

For example, an 18-decimal borrow of `980_000_000 * 10^18` base units mints approximately `9.8e35` scaled debt shares at an initial `RAY` index. [3](#0-2) [19](#0-18) 

That book overflows once `borrowed * borrow_index / RAY > i128::MAX`, which corresponds to a borrow index of roughly `173.5 * RAY`. [1](#0-0) [7](#0-6) 

The substantial capitalization and index-growth prerequisites make exploitation conditional rather than universally reachable, but the resulting failure is permanent and affects all users of the market. [11](#0-10) [5](#0-4) 

### Recommendation
Enforce aggregate scaled-supply and scaled-debt ceilings that guarantee `scaled * configured_maximum_index / RAY <= i128::MAX` before minting additional shares. [10](#0-9) [20](#0-19) 

The bound should be applied consistently to supply, borrow, flash-position debt minting, strategy debt minting, liquidation credits, and revenue-share minting rather than relying only on asset-unit caps. [21](#0-20) [22](#0-21) 

Alternatively, reduce the configured index ceilings so that the largest admitted market remains representable under the maximum possible index. [10](#0-9) 

### Proof of Concept
1. As an unprivileged caller, invoke controller `supply` with `account_id = 0` and assets containing approximately `1_000_000_000 * 10^18` units of an 18-decimal borrow asset plus enough collateral to remain solvent. [17](#0-16) [23](#0-22) 

2. Invoke controller `borrow` for approximately `980_000_000 * 10^18` units of the same asset, minting roughly `9.8e35` scaled debt shares. [24](#0-23) [19](#0-18) 

3. Maintain the borrowing account’s collateralization until the market borrow index exceeds approximately `173.5 * RAY`; no privileged call is needed during this period. [25](#0-24) 

4. Submit any market operation, such as `repay(caller, account_id, [(asset, 1)])`; the pool calls `global_sync`, `accrue_step` evaluates `borrowed * borrow_index / RAY`, and the result no longer fits in `i128`. [13](#0-12) [5](#0-4) [8](#0-7) 

5. The transaction panics before `mark_accrued` or `commit`, leaving the stale timestamp and overflowing aggregate unchanged, so every later repay, withdraw, liquidation, or index update repeats the same failure. [11](#0-10) [12](#0-11)

### Citations

**File:** common/src/rates/simulate.rs (L60-69)
```rust
    let borrowed_original = scaled_to_original(env, borrowed, borrow_index);
    let supplied_original = scaled_to_original(env, supplied, supply_index);
    let util = utilization(env, borrowed_original, supplied_original);
    let borrow_rate = calculate_borrow_rate(env, util, params);
    let interest_factor = compound_interest(env, borrow_rate, delta_ms);

    let new_borrow_index = update_borrow_index(env, borrow_index, interest_factor);

    let (supplier_rewards, protocol_fee) =
        calculate_supplier_rewards(env, params, borrowed, new_borrow_index, borrow_index);
```

**File:** contracts/pool/src/ops/mod.rs (L29-33)
```rust
/// Loads a market cache and accrues interest through the current ledger time.
pub(crate) fn synced_market(env: &Env, hub_asset: &HubAssetKey) -> Cache {
    let mut cache = Cache::load(env, hub_asset);
    interest::global_sync(env, &mut cache);
    cache
```

**File:** contracts/pool/src/ops/mod.rs (L42-46)
```rust
/// Validates `action.amount ≥ 0`, syncs the market, and returns (cache, scaled position).
pub(crate) fn load_leg(env: &Env, action: &PoolAction) -> (Cache, Ray) {
    require_nonneg_amount(env, action.amount);
    let cache = synced_market(env, &action.hub_asset);
    (cache, Ray::from(action.position.scaled_amount))
```

**File:** common/src/rates/scaling.rs (L12-15)
```rust
/// Converts a scaled `Ray` amount to its original (unscaled) value by
/// multiplying by `index`, rounding half up.
pub fn scaled_to_original(env: &Env, scaled: Ray, index: Ray) -> Ray {
    scaled.mul(env, index)
```

**File:** common/src/rates/scaling.rs (L52-56)
```rust
/// Converts an asset-unit `amount` to a scaled borrow `Ray` using ceiling
/// rounding relative to `borrow_index`.
pub fn calculate_scaled_borrow(env: &Env, amount: i128, decimals: u32, borrow_index: Ray) -> Ray {
    Ray::from_asset(env, amount, decimals).div_ceil(env, borrow_index)
}
```

**File:** common/src/math/fp.rs (L49-52)
```rust
    /// Multiplies two ray values, rounding the result half up.
    pub fn mul(self, env: &Env, other: Ray) -> Ray {
        Ray(fp_core::mul_div_half_up(env, self.0, other.0, RAY))
    }
```

**File:** common/src/math/fp_core.rs (L116-117)
```rust
    try_mul_div_half_up(env, x, y, d)
        .unwrap_or_else(|| panic_with_error!(env, GenericError::MathOverflow))
```

**File:** common/src/math/fp_core.rs (L139-143)
```rust
    x256.mul(&y256)
        .add(&I256::from_i128(env, half))
        .div(&d256)
        .to_i128()
}
```

**File:** common/src/rates/index.rs (L13-18)
```rust
pub fn update_borrow_index(env: &Env, old_index: Ray, interest_factor: Ray) -> Ray {
    let new_index = old_index.mul(env, interest_factor);
    if new_index.raw() > MAX_BORROW_INDEX_RAY {
        return Ray::from(MAX_BORROW_INDEX_RAY);
    }
    new_index
```

**File:** contracts/pool/src/interest.rs (L25-32)
```rust
    let mut remaining = cache.elapsed_ms();
    while let Some(nonzero) = NonZeroU64::new(remaining) {
        let chunk = nonzero.get().min(MAX_COMPOUND_DELTA_MS);
        accrue_chunk(env, cache, chunk);
        remaining = remaining.saturating_sub(chunk);
    }

    cache.mark_accrued();
```

**File:** contracts/pool/src/ops/market.rs (L68-71)
```rust
    for hub_asset in hub_assets.iter() {
        let mut cache = Cache::load(env, &hub_asset);
        interest::global_sync(env, &mut cache);
        events::emit_market_state(env, cache.commit());
```

**File:** contracts/controller/src/lib.rs (L90-94)
```rust
    /// Supplies `assets` as collateral and returns the account id; `account_id = 0`
    /// creates an account in `spoke_id`. Third parties may only top up existing
    /// supply positions; owners and delegates may add assets.
    #[when_not_paused]
    fn supply(
```

**File:** contracts/controller/src/lib.rs (L95-101)
```rust
        env: Env,
        caller: Address,
        account_id: u64,
        spoke_id: u32,
        assets: Vec<(HubAssetKey, i128)>,
    ) -> u64 {
        positions::process_supply(&env, &caller, account_id, spoke_id, &assets)
```

**File:** contracts/controller/src/lib.rs (L107-114)
```rust
    fn borrow(
        env: Env,
        caller: Address,
        account_id: u64,
        borrows: Vec<(HubAssetKey, i128)>,
        to: Option<Address>,
    ) {
        positions::process_borrow(&env, &caller, account_id, &borrows, to);
```

**File:** contracts/controller/src/lib.rs (L130-133)
```rust
    /// Repays `account_id`'s debt using measured payments from the caller.
    /// Anyone may repay; excess payments are refunded to the caller.
    fn repay(env: Env, caller: Address, account_id: u64, payments: Vec<(HubAssetKey, i128)>) {
        positions::process_repay(&env, &caller, account_id, &payments);
```

**File:** contracts/controller/src/lib.rs (L144-148)
```rust
    fn liquidate(
        env: Env,
        liquidator: Address,
        account_id: u64,
        debt_payments: Vec<(HubAssetKey, i128)>,
```

**File:** contracts/pool/src/ops/repay.rs (L40-47)
```rust
pub(crate) fn accounting(env: &Env, action: &PoolAction) -> RepayOutcome {
    let (mut cache, position) = ops::load_leg(env, action);
    let amount = action.amount;

    let (burned, overpayment) = cache.resolve_repay(amount, position);
    let net_repay = amount
        .checked_sub(overpayment)
        .unwrap_or_else(|| panic_with_error!(env, GenericError::MathOverflow));
```

**File:** contracts/pool/src/ops/withdraw.rs (L63-80)
```rust
    let (mut cache, position) = ops::load_leg(env, &entry.action);

    let (burned, gross_amount) = resolve_close_or_partial(&cache, entry.action.amount, position);
    // Burn first: `protocol_fee_shares` caps the fee mint at `i128::MAX - supplied`.
    let remaining = burn_position(env, &mut cache, position, burned);
    let net_transfer = withhold_liquidation_fee(
        env,
        &mut cache,
        gross_amount,
        is_liquidation,
        entry.protocol_fee,
    );

    // A footprint-only close must not add a utilization gate to same-market
    // net settlement: it burns no shares and moves no cash.
    let empty_close = position.raw() == 0 && entry.action.amount == i128::MAX;
    gate_and_debit(env, &mut cache, net_transfer, is_liquidation || empty_close);

```

**File:** contracts/pool/src/ops/borrow.rs (L63-78)
```rust
pub(crate) fn mint_debt(env: &Env, cache: &mut Cache, position: &mut Ray, amount: i128) {
    require_positive_amount(env, amount);
    cache.require_reserves(amount);
    guards::require_liquidation_buffer(env, cache, amount);

    let minted = cache.calculate_scaled_borrow(amount);

    assert_with_error!(
        env,
        minted.raw() > 0,
        GenericError::BorrowRoundsToZeroShares
    );

    *position = position.checked_add(env, minted);
    cache.mint_debt(minted);
    guards::require_utilization_below_max(env, cache);
```

**File:** contracts/pool/src/cache/shares.rs (L15-28)
```rust
    pub(crate) fn mint_supply(&mut self, scaled: Ray) {
        self.supplied = self.supplied.checked_add(&self.env, scaled);
    }

    /// Burns scaled supply shares, then asserts revenue ≤ total supply.
    pub(crate) fn burn_supply(&mut self, scaled: Ray) {
        self.supplied = self.supplied.checked_sub(&self.env, scaled);
        self.require_revenue_backed();
    }

    /// Mints scaled debt shares into the market total.
    pub(crate) fn mint_debt(&mut self, scaled: Ray) {
        self.borrowed = self.borrowed.checked_add(&self.env, scaled);
    }
```

**File:** contracts/pool/src/ops/supply.rs (L28-39)
```rust
    let minted = cache.calculate_scaled_supply(amount);
    assert_with_error!(
        env,
        amount == 0 || minted.raw() > 0,
        GenericError::SupplyRoundsToZeroShares
    );

    position = position.checked_add(env, minted);
    cache.mint_supply(minted);

    cache.credit_cash(amount);

```
