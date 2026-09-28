### Title
RAY value overflow during interest accrual permanently freezes an oversized market - (File: common/src/rates/simulate.rs)

### Summary
A market can grow until `scaled_amount * index` no longer fits in `i128`, after which every operation that touches that market panics before mutating state. [1](#0-0) [2](#0-1)  The repository's regression test demonstrates that this blocks index updates, withdrawals, and repayments before the nominal borrow-index ceiling is reached. [3](#0-2) 

### Finding Description
An unprivileged user can create and leverage an account through `Controller::supply` and `Controller::borrow`; repayment is also permissionless through `Controller::repay`. [4](#0-3) [5](#0-4) 

Every pool repayment, withdrawal, borrow, or market-index update first loads the market and executes `interest::global_sync`. [2](#0-1)  `global_sync` accrues elapsed time in chunks and only marks the market current after all chunks succeed. [6](#0-5) 

Each accrual chunk computes `scaled_to_original(borrowed, borrow_index)` and `scaled_to_original(supplied, supply_index)` before calculating utilization, rates, rewards, and the next indexes. [7](#0-6)  `scaled_to_original` is a checked RAY multiplication that panics when the resulting value cannot fit in `i128`. [8](#0-7) 

The index ceiling only bounds the index value after multiplication; it does not bound `scaled_amount * index`, so an extremely large book can overflow the value domain while the index remains below `MAX_BORROW_INDEX_RAY`. [9](#0-8) [10](#0-9)  The project documentation explicitly notes that accrued market totals can exceed the RAY domain before the index ceiling and block repayment or withdrawal because those operations accrue first. [11](#0-10) 

### Impact Explanation
Once the market crosses this arithmetic boundary, all state-changing operations for that market fail deterministically because they must complete accrual before repayment, withdrawal, seizure, or other mutations. [2](#0-1) [12](#0-11)  This permanently freezes supplier cash and prevents borrowers or liquidators from reducing debt through the affected market, matching the accepted impact class of permanent freezing of user funds and contract inability to operate. [13](#0-12) 

### Likelihood Explanation
Exploitation requires an extraordinarily large token-denominated book and enough elapsed time at high utilization for the index to grow the aggregate scaled value beyond `i128::MAX`. [14](#0-13)  The checked scenario uses one billion whole 18-decimal tokens, 98% utilization, and repeated yearly advancement until `MathOverflow`; it also depends on deployment caps and utilization settings permitting that exposure. [15](#0-14)  These requirements make practical likelihood low for ordinary markets, but the path is reachable by an unprivileged account whenever a listed asset's total liquidity and configured caps permit the required book size. [4](#0-3) 

### Recommendation
Enforce a market-level invariant that projected aggregate supply and debt values remain representable before allowing additional supply or debt exposure. [16](#0-15)  Preferably, bound `scaled_amount * MAX_ALLOWED_INDEX` at admission time or use a wider internal aggregate representation for accrual; alternatively, clamp the effective index for each book at the largest value that keeps `scaled_amount * index` within `i128` instead of panicking. [9](#0-8)  Regression coverage should assert that repayment, withdrawal, liquidation, and index synchronization remain executable as a market approaches the numeric boundary. [2](#0-1) 

### Proof of Concept
1. An attacker creates an account with `Controller::supply(attacker, 0, spoke_id, [(big_asset, principal)])`, where `principal` is on the order of `1_000_000_000 * 10^asset_decimals`, then supplies sufficient collateral and calls `Controller::borrow(attacker, account_id, [(big_asset, debt)], Some(attacker))` to establish sustained high utilization. [4](#0-3) 
2. Ledger time advances while the large debt remains outstanding, allowing repeated accrual chunks to increase `borrow_index` and the corresponding aggregate debt value. [6](#0-5) 
3. When `borrowed * borrow_index` exceeds `i128::MAX`, the next `repay`, `withdraw`, `liquidate`, or index-sync path enters `global_sync`, panics inside `accrue_step`, and leaves `last_timestamp` unchanged. [17](#0-16) [18](#0-17) 
4. The existing regression test reproduces this sequence and confirms `MathOverflow` for `update_indexes`, `withdraw`, and `repay` while the stored index remains below `MAX_BORROW_INDEX_RAY`. [19](#0-18)

### Citations

**File:** common/src/rates/scaling.rs (L12-16)
```rust
/// Converts a scaled `Ray` amount to its original (unscaled) value by
/// multiplying by `index`, rounding half up.
pub fn scaled_to_original(env: &Env, scaled: Ray, index: Ray) -> Ray {
    scaled.mul(env, index)
}
```

**File:** common/src/rates/scaling.rs (L52-67)
```rust
/// Converts an asset-unit `amount` to a scaled borrow `Ray` using ceiling
/// rounding relative to `borrow_index`.
pub fn calculate_scaled_borrow(env: &Env, amount: i128, decimals: u32, borrow_index: Ray) -> Ray {
    Ray::from_asset(env, amount, decimals).div_ceil(env, borrow_index)
}

/// Converts an asset-unit `amount` to a scaled borrow `Ray` using floor
/// rounding relative to `borrow_index`.
pub fn calculate_scaled_borrow_floor(
    env: &Env,
    amount: i128,
    decimals: u32,
    borrow_index: Ray,
) -> Ray {
    Ray::from_asset(env, amount, decimals).div_floor(env, borrow_index)
}
```

**File:** contracts/pool/src/ops/mod.rs (L29-45)
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
```

**File:** tests/test-harness/tests/controller/large_positions_and_long_horizons.rs (L315-356)
```rust
/// The cliff. A billion whole tokens is `1e36` raw ray; the value ceiling is
/// `i128::MAX`, 170 times that. At the XLM curve's steep segment the index
/// grows past 170x in a few years, and the next accrual panics inside
/// `scaled_to_original`. Every verb accrues first, so the market freezes:
/// no repay, no withdraw, no liquidation. The index cap never engages.
#[test]
fn a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap() {
    let mut t = LendingTest::new()
        .with_market(big("BIG18", 18, xlm_curve()))
        .with_market(col())
        .with_max_utilization_disabled_all_markets()
        .build();
    lift_caps(&t, "BIG18", 18);
    lift_caps(&t, "COL", 7);
    let principal = BILLION * 10i128.pow(18);
    t.supply_raw(BOB, "BIG18", principal);
    let debt = principal / 100 * 98;
    t.supply_raw(ALICE, "COL", BILLION * 10_000_000 * 3);
    t.borrow_raw(ALICE, "BIG18", debt);

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
    };
    let failed: Result<(), soroban_sdk::Error> = Err(failure);
    assert_contract_error(failed, errors::MATH_OVERFLOW);
    let last = book(&t, "BIG18");
    assert!(
        last.borrow_index < MAX_BORROW_INDEX_RAY,
        "the index cap did not engage before the value overflow"
    );
    // The market is frozen: exits and repayments accrue first and hit the same panic.
    assert_contract_error(t.try_withdraw_raw(BOB, "BIG18", 1), errors::MATH_OVERFLOW);
    assert_contract_error(t.try_repay(ALICE, "BIG18", 1.0), errors::MATH_OVERFLOW);
```

**File:** contracts/controller/src/lib.rs (L90-114)
```rust
    /// Supplies `assets` as collateral and returns the account id; `account_id = 0`
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

**File:** contracts/controller/src/lib.rs (L130-134)
```rust
    /// Repays `account_id`'s debt using measured payments from the caller.
    /// Anyone may repay; excess payments are refunded to the caller.
    fn repay(env: Env, caller: Address, account_id: u64, payments: Vec<(HubAssetKey, i128)>) {
        positions::process_repay(&env, &caller, account_id, &payments);
    }
```

**File:** contracts/pool/src/interest.rs (L20-32)
```rust
pub(crate) fn global_sync(env: &Env, cache: &mut Cache) {
    if !cache.needs_accrual() {
        return;
    }

    let mut remaining = cache.elapsed_ms();
    while let Some(nonzero) = NonZeroU64::new(remaining) {
        let chunk = nonzero.get().min(MAX_COMPOUND_DELTA_MS);
        accrue_chunk(env, cache, chunk);
        remaining = remaining.saturating_sub(chunk);
    }

    cache.mark_accrued();
```

**File:** common/src/rates/simulate.rs (L51-70)
```rust
pub fn accrue_step(
    env: &Env,
    params: &MarketParams,
    borrowed: Ray,
    supplied: Ray,
    borrow_index: Ray,
    supply_index: Ray,
    delta_ms: u64,
) -> AccrualStep {
    let borrowed_original = scaled_to_original(env, borrowed, borrow_index);
    let supplied_original = scaled_to_original(env, supplied, supply_index);
    let util = utilization(env, borrowed_original, supplied_original);
    let borrow_rate = calculate_borrow_rate(env, util, params);
    let interest_factor = compound_interest(env, borrow_rate, delta_ms);

    let new_borrow_index = update_borrow_index(env, borrow_index, interest_factor);

    let (supplier_rewards, protocol_fee) =
        calculate_supplier_rewards(env, params, borrowed, new_borrow_index, borrow_index);

```

**File:** common/src/math/fp.rs (L49-52)
```rust
    /// Multiplies two ray values, rounding the result half up.
    pub fn mul(self, env: &Env, other: Ray) -> Ray {
        Ray(fp_core::mul_div_half_up(env, self.0, other.0, RAY))
    }
```

**File:** common/src/rates/index.rs (L11-19)
```rust
/// Applies `interest_factor` to `old_index` to produce the new borrow index,
/// capped at `MAX_BORROW_INDEX_RAY`.
pub fn update_borrow_index(env: &Env, old_index: Ray, interest_factor: Ray) -> Ray {
    let new_index = old_index.mul(env, interest_factor);
    if new_index.raw() > MAX_BORROW_INDEX_RAY {
        return Ray::from(MAX_BORROW_INDEX_RAY);
    }
    new_index
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

**File:** docs/reference/formulas.md (L432-437)
```markdown
The token-to-RAY maximum is also the admitted cap maximum. Accrued position
values and market totals must independently fit the RAY domain; valid caps and
bounded indexes do not guarantee that future accrual fits. Value overflow can
occur before the index ceiling and block repayment/withdrawal because those
operations accrue first. At the borrow-index ceiling, further accrual produces
no borrower interest. No dedicated ceiling alarm is emitted.
```

**File:** contracts/pool/src/ops/withdraw.rs (L57-65)
```rust
pub(crate) fn accounting(
    env: &Env,
    is_liquidation: bool,
    entry: &PoolWithdrawEntry,
) -> WithdrawOutcome {
    require_nonneg_amount(env, entry.protocol_fee);
    let (mut cache, position) = ops::load_leg(env, &entry.action);

    let (burned, gross_amount) = resolve_close_or_partial(&cache, entry.action.amount, position);
```
