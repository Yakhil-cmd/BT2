### Title
Overflow in accrual permanently freezes an over-cap debt market - (`common/src/rates/simulate.rs`)

### Summary

`accrue_step` computes `borrowed * borrow_index` in an `i128`-backed `Ray` before enforcing the borrow-index ceiling, so a sufficiently large market panics with `MathOverflow` while the index is still below its configured cap. Because every market mutation synchronizes interest first, the panic becomes a permanent liveness failure for that market’s debt and supply. [1](#0-0) [2](#0-1) [3](#0-2) 

### Finding Description

`scaled_to_original` multiplies scaled debt by the borrow index through `Ray::mul`, whose result must fit in `i128`. [4](#0-3) [5](#0-4) 

The market’s effective domain is therefore `borrowed * borrow_index <= i128::MAX`, but the borrow-index ceiling alone allows an index multiplier of `10^9` raw-RAY units. [6](#0-5) 

Before `update_borrow_index` can clamp a new index, `accrue_step` computes the current debt value for utilization; if that already exceeds `i128::MAX`, accrual reverts. [7](#0-6) 

The same problem exists for the reward split, which separately multiplies `borrowed` by both the old and new borrow indexes. [8](#0-7) 

The harness reproduces the boundary with a one-billion-whole-token, 18-decimal market and demonstrates that the stored borrow index remains below `MAX_BORROW_INDEX_RAY` when accrual fails. [9](#0-8) [10](#0-9) 

### Impact Explanation

Once `borrowed * borrow_index` exceeds `i128::MAX`, every pool operation that calls `synced_market` or `load_leg` panics before performing its action. [11](#0-10) 

That blocks the strongest user-reachable recovery paths: `update_indexes`, `withdraw`, and permissionless `repay`; liquidation also cannot proceed because debt settlement must first load an interest-synced market. [12](#0-11) [13](#0-12) 

The regression test confirms that both withdrawal and repayment hit `MathOverflow` after the condition is reached. [14](#0-13) 

As a result, supplied tokens and repayment capacity are permanently frozen unless the contract is upgraded or migrated; ordinary parameter changes cannot shrink the nonzero scaled debt without first executing the accrual path that panics. [15](#0-14) [16](#0-15) 

### Likelihood Explanation

This is not triggerable by dust or ordinary positions: it requires a legally listed high-decimal market whose configured caps admit enough scaled debt that index growth can push the product past `i128::MAX`. [17](#0-16) 

The triggering actions are nevertheless unprivileged market operations: users supply and borrow their own assets, and any caller can later invoke `update_indexes`. [18](#0-17) [13](#0-12) 

The high capital requirement and dependence on sustained accrual reduce the severity, but the resulting market-wide denial of withdrawals, repayments, and liquidations qualifies as permanent freezing of user funds. [19](#0-18) [14](#0-13) 

### Recommendation

Enforce an index-aware scaled-debt bound before borrow minting: `scaled_borrowed <= i128::MAX / current_borrow_index`, using the maximum future index accepted by the market when the bound must remain safe after accrual. [6](#0-5) [20](#0-19) 

Also remove the requirement to materialize `borrowed * borrow_index` in an `i128` during utilization and reward calculations: use a wider intermediate, or compare/divide scaled quantities before multiplication, and only return a representable `Ray` after explicit bounds checks. [21](#0-20) 

Add a regression bound at market initialization and borrow/supply caps so `MAX_BORROW_INDEX_RAY` cannot imply an overflow of the aggregate debt calculation, and keep the existing harness case asserting that the index cap engages before the value ceiling. [2](#0-1) [10](#0-9) 

### Proof of Concept

1. Configure an 18-decimal market with a steep but valid interest-rate curve and maximum-allowed supply/borrow caps, then call `supply(caller, 0, spoke_id, [(BIG18, 1_000_000_000 * 10^18)])` to create a one-billion-token supply position. [22](#0-21) [23](#0-22) 
2. Supply sufficient collateral through `supply` and call `borrow(caller, account_id, [(BIG18, 980_000_000 * 10^18)], None)`, leaving utilization at 98%. [24](#0-23) [25](#0-24) 
3. Allow ledger time to advance and invoke the permissionless `update_indexes(caller, [BIG18])`; repeat until `borrowed * borrow_index > i128::MAX`. [13](#0-12) [26](#0-25) 
4. The call fails with `MathOverflow` while `borrow_index < MAX_BORROW_INDEX_RAY`, proving the cap did not prevent the aggregate-value overflow. [10](#0-9) 
5. Subsequent `withdraw` and `repay` calls fail identically because both paths call `global_sync` before changing the position. [3](#0-2) [14](#0-13)

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

**File:** common/src/rates/index.rs (L13-18)
```rust
pub fn update_borrow_index(env: &Env, old_index: Ray, interest_factor: Ray) -> Ray {
    let new_index = old_index.mul(env, interest_factor);
    if new_index.raw() > MAX_BORROW_INDEX_RAY {
        return Ray::from(MAX_BORROW_INDEX_RAY);
    }
    new_index
```

**File:** common/src/rates/index.rs (L80-86)
```rust
    let old_total_debt = borrowed.mul(env, old_borrow_index);
    let new_total_debt = borrowed.mul(env, new_borrow_index);

    let accrued_interest = new_total_debt.checked_sub(env, old_total_debt);

    let protocol_fee = params.reserve_factor.apply_to_ray(env, accrued_interest);
    let supplier_rewards = accrued_interest.checked_sub(env, protocol_fee);
```

**File:** contracts/pool/src/ops/mod.rs (L29-46)
```rust
/// Loads a market cache and accrues interest through the current ledger time.
pub(crate) fn synced_market(env: &Env, hub_asset: &HubAssetKey) -> Cache {
    let mut cache = Cache::load(env, hub_asset);
    interest::global_sync(env, &mut cache);
    cache
}

/// Renews instance TTL, then loads and accrues the market.
pub(crate) fn renewed_market(env: &Env, hub_asset: &HubAssetKey) -> Cache {
    renew_instance(env);
    synced_market(env, hub_asset)
}

/// Validates `action.amount ≥ 0`, syncs the market, and returns (cache, scaled position).
pub(crate) fn load_leg(env: &Env, action: &PoolAction) -> (Cache, Ray) {
    require_nonneg_amount(env, action.amount);
    let cache = synced_market(env, &action.hub_asset);
    (cache, Ray::from(action.position.scaled_amount))
```

**File:** common/src/rates/scaling.rs (L12-16)
```rust
/// Converts a scaled `Ray` amount to its original (unscaled) value by
/// multiplying by `index`, rounding half up.
pub fn scaled_to_original(env: &Env, scaled: Ray, index: Ray) -> Ray {
    scaled.mul(env, index)
}
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

**File:** common/src/constants/pool.rs (L18-23)
```rust
/// Ceiling the borrow index is clamped to after growth, in raw ray units.
pub const MAX_BORROW_INDEX_RAY: i128 = 1_000_000_000_000_000_000_000_000_000_000_000_000;

/// Ceiling the supply index is clamped to after growth, in raw ray units.
/// Equal to [`MAX_BORROW_INDEX_RAY`].
pub const MAX_SUPPLY_INDEX_RAY: i128 = MAX_BORROW_INDEX_RAY;
```

**File:** tests/test-harness/tests/controller/large_positions_and_long_horizons.rs (L26-38)
```rust
/// Steep XLM stress curve: 175 percent max borrow rate, optimal at 75 percent.
fn xlm_curve() -> MarketParamsPreset {
    MarketParamsPreset {
        max_borrow_rate: RAY * 175 / 100,
        base_borrow_rate: RAY / 100,
        slope1: RAY * 4 / 100,
        slope2: RAY * 10 / 100,
        slope3: RAY * 150 / 100,
        mid_utilization: RAY * 50 / 100,
        optimal_utilization: RAY * 75 / 100,
        max_utilization: RAY,
        reserve_factor: 2000,
    }
```

**File:** tests/test-harness/tests/controller/large_positions_and_long_horizons.rs (L81-94)
```rust
fn lift_caps(t: &LendingTest, asset: &str, decimals: u32) {
    let cap = max_cap_for_decimals(decimals);
    let cfg = t.get_asset_config(asset);
    t.edit_asset_in_spoke_caps(
        asset,
        HARNESS_SPOKE,
        true,
        true,
        cfg.loan_to_value,
        cfg.liquidation_threshold,
        cfg.liquidation_bonus,
        cap,
        cap,
    );
```

**File:** tests/test-harness/tests/controller/large_positions_and_long_horizons.rs (L315-321)
```rust
/// The cliff. A billion whole tokens is `1e36` raw ray; the value ceiling is
/// `i128::MAX`, 170 times that. At the XLM curve's steep segment the index
/// grows past 170x in a few years, and the next accrual panics inside
/// `scaled_to_original`. Every verb accrues first, so the market freezes:
/// no repay, no withdraw, no liquidation. The index cap never engages.
#[test]
fn a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap() {
```

**File:** tests/test-harness/tests/controller/large_positions_and_long_horizons.rs (L329-333)
```rust
    let principal = BILLION * 10i128.pow(18);
    t.supply_raw(BOB, "BIG18", principal);
    let debt = principal / 100 * 98;
    t.supply_raw(ALICE, "COL", BILLION * 10_000_000 * 3);
    t.borrow_raw(ALICE, "BIG18", debt);
```

**File:** tests/test-harness/tests/controller/large_positions_and_long_horizons.rs (L335-345)
```rust
    let mut years = 0u32;
    let failure = loop {
        years += 1;
        assert!(
            years <= 40,
            "no cliff within 40 years; the bound in docs/reference/formulas.md is wrong"
        );
        t.advance_time(YEAR_SECS);
        if let Err(e) = t.try_update_indexes_for(&["BIG18"]) {
            break e;
        }
```

**File:** tests/test-harness/tests/controller/large_positions_and_long_horizons.rs (L347-353)
```rust
    let failed: Result<(), soroban_sdk::Error> = Err(failure);
    assert_contract_error(failed, errors::MATH_OVERFLOW);
    let last = book(&t, "BIG18");
    assert!(
        last.borrow_index < MAX_BORROW_INDEX_RAY,
        "the index cap did not engage before the value overflow"
    );
```

**File:** tests/test-harness/tests/controller/large_positions_and_long_horizons.rs (L354-356)
```rust
    // The market is frozen: exits and repayments accrue first and hit the same panic.
    assert_contract_error(t.try_withdraw_raw(BOB, "BIG18", 1), errors::MATH_OVERFLOW);
    assert_contract_error(t.try_repay(ALICE, "BIG18", 1.0), errors::MATH_OVERFLOW);
```

**File:** contracts/controller/src/lib.rs (L91-114)
```rust
    /// creates an account in `spoke_id`. Third parties may only top up existing
    /// supply positions; owners and delegates may add assets.
    #[when_not_paused]
    fn supply(
        env: Env,
        caller: Address,
        account_id: u64,
        spoke_id: u32,
        assets: Vec<(HubAssetKey, i128)>,
    ) -> u64 {
        positions::process_supply(&env, &caller, account_id, spoke_id, &assets)
    }

    /// Borrows against `account_id`'s collateral, paying `to` or the caller.
    /// Requires owner or delegate authorization and post-borrow solvency.
    #[when_not_paused]
    fn borrow(
        env: Env,
        caller: Address,
        account_id: u64,
        borrows: Vec<(HubAssetKey, i128)>,
        to: Option<Address>,
    ) {
        positions::process_borrow(&env, &caller, account_id, &borrows, to);
```

**File:** contracts/controller/src/lib.rs (L117-133)
```rust
    /// Withdraws collateral to `to` or the caller and returns actual amounts in
    /// asset units. Zero withdraws an asset's full position. Requires owner or
    /// delegate authorization and post-withdrawal solvency.
    fn withdraw(
        env: Env,
        caller: Address,
        account_id: u64,
        withdrawals: Vec<(HubAssetKey, i128)>,
        to: Option<Address>,
    ) -> Vec<(HubAssetKey, i128)> {
        positions::process_withdraw(&env, &caller, account_id, &withdrawals, to)
    }

    /// Repays `account_id`'s debt using measured payments from the caller.
    /// Anyone may repay; excess payments are refunded to the caller.
    fn repay(env: Env, caller: Address, account_id: u64, payments: Vec<(HubAssetKey, i128)>) {
        positions::process_repay(&env, &caller, account_id, &payments);
```

**File:** contracts/controller/src/lib.rs (L367-371)
```rust
    /// Accrues pool borrow and supply indexes for `assets`. Permissionless;
    /// requires caller authorization.
    #[when_not_paused]
    fn update_indexes(env: Env, caller: Address, assets: Vec<HubAssetKey>) {
        markets::update_indexes(&env, caller, assets);
```

**File:** contracts/pool/src/ops/withdraw.rs (L57-64)
```rust
pub(crate) fn accounting(
    env: &Env,
    is_liquidation: bool,
    entry: &PoolWithdrawEntry,
) -> WithdrawOutcome {
    require_nonneg_amount(env, entry.protocol_fee);
    let (mut cache, position) = ops::load_leg(env, &entry.action);

```

**File:** contracts/pool/src/ops/repay.rs (L36-45)
```rust
/// Accrues interest, resolves the repay amount into burned debt shares and
/// overpayment, burns the shares, and credits the net repay to cash without
/// transferring the overpayment refund. Panics if a positive net repay would
/// burn zero scaled shares.
pub(crate) fn accounting(env: &Env, action: &PoolAction) -> RepayOutcome {
    let (mut cache, position) = ops::load_leg(env, action);
    let amount = action.amount;

    let (burned, overpayment) = cache.resolve_repay(amount, position);
    let net_repay = amount
```
