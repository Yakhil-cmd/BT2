### Title
Interest accrual can permanently freeze an oversized market before the borrow-index cap - ([File: contracts/pool/src/interest.rs])

### Summary
A sufficiently large borrow book can make `borrowed * borrow_index` overflow `i128` during accrual before `MAX_BORROW_INDEX_RAY` is reached. Because every pool mutation synchronizes interest first, this permanently blocks repayment, withdrawal, liquidation, recapitalization, and further index updates for that market. [1](#0-0) [2](#0-1) 

### Finding Description
`global_sync` accrues every elapsed interval through `accrue_chunk`, which calls `accrue_step` before committing state. [3](#0-2) [4](#0-3)  `calculate_supplier_rewards` multiplies the scaled debt by both the old and new borrow indexes using panicking RAY multiplication, so an unrepresentable total debt aborts the transaction. [5](#0-4) [6](#0-5)  Although `update_borrow_index` clamps the index to `MAX_BORROW_INDEX_RAY`, the debt-value multiplication can overflow at an index far below that cap when `borrowed` is sufficiently large. [7](#0-6) [8](#0-7) 

### Impact Explanation
All suppliers’ tokens in the affected market become permanently frozen, borrowers cannot repay, liquidators cannot reduce risk, and recapitalization cannot repair the book because each path loads an interest-synced market. [9](#0-8) [10](#0-9) [11](#0-10) [12](#0-11)  The repository’s stress test demonstrates that withdrawal and repayment both fail with `MathOverflow` after the overflow point, while the stored borrow index remains below `MAX_BORROW_INDEX_RAY`. [13](#0-12) 

### Likelihood Explanation
An unprivileged account can create the prerequisite state through ordinary `supply` and `borrow` calls, and any user can subsequently trigger the frozen state through `update_indexes`; no privileged oracle, upgrade, leaked key, or malformed parameter is required. [14](#0-13) [15](#0-14)  The attack requires a very large market, enough collateral to borrow at sustained high utilization, and enough elapsed time for index growth, so it is less practical than a direct theft but deterministically reproducible once those market conditions exist. [16](#0-15) 

### Recommendation
Compute an effective index bound from the live scaled debt before evaluating rewards, such as `min(MAX_BORROW_INDEX_RAY, i128::MAX / borrowed_raw)`, or perform the debt-delta calculation in a wider type with an explicit safe clamp. [17](#0-16)  The market should also reject supply or borrow growth that would make `borrowed * MAX_BORROW_INDEX_RAY`, or the lower configured operational ceiling, unrepresentable rather than allowing the book to enter an unrecoverable accrual state. [8](#0-7) [18](#0-17) 

### Proof of Concept
1. The attacker supplies approximately `1_000_000_000 * 10^18` base units of an 18-decimal asset through controller `supply`, using a market whose configured caps admit that amount. [19](#0-18) 
2. The attacker supplies collateral and calls controller `borrow` for approximately `98%` of that market’s liquidity, producing a scaled debt near the representable-value boundary. [20](#0-19) 
3. As ledger time advances, anyone calls controller `update_indexes` for `hub_assets = [HubAssetKey { hub_id, asset }]`; the pool accrues in bounded chunks and repeatedly grows the borrow index. [15](#0-14) [21](#0-20) 
4. Once `borrowed * new_borrow_index` exceeds `i128::MAX`, `calculate_supplier_rewards` panics with `GenericError::MathOverflow` before the index cap can be committed. [2](#0-1) [22](#0-21) 
5. Subsequent controller `withdraw`, `repay`, `liquidate`, `clean_bad_debt`, `recapitalize`, or another `update_indexes` call reaches the same initial market synchronization and fails again, leaving all cash backing the market inaccessible. [9](#0-8) [23](#0-22)

### Citations

**File:** contracts/pool/src/ops/mod.rs (L29-34)
```rust
/// Loads a market cache and accrues interest through the current ledger time.
pub(crate) fn synced_market(env: &Env, hub_asset: &HubAssetKey) -> Cache {
    let mut cache = Cache::load(env, hub_asset);
    interest::global_sync(env, &mut cache);
    cache
}
```

**File:** common/src/rates/index.rs (L11-18)
```rust
/// Applies `interest_factor` to `old_index` to produce the new borrow index,
/// capped at `MAX_BORROW_INDEX_RAY`.
pub fn update_borrow_index(env: &Env, old_index: Ray, interest_factor: Ray) -> Ray {
    let new_index = old_index.mul(env, interest_factor);
    if new_index.raw() > MAX_BORROW_INDEX_RAY {
        return Ray::from(MAX_BORROW_INDEX_RAY);
    }
    new_index
```

**File:** common/src/rates/index.rs (L73-88)
```rust
pub fn calculate_supplier_rewards(
    env: &Env,
    params: &MarketParams,
    borrowed: Ray,
    new_borrow_index: Ray,
    old_borrow_index: Ray,
) -> (Ray, Ray) {
    let old_total_debt = borrowed.mul(env, old_borrow_index);
    let new_total_debt = borrowed.mul(env, new_borrow_index);

    let accrued_interest = new_total_debt.checked_sub(env, old_total_debt);

    let protocol_fee = params.reserve_factor.apply_to_ray(env, accrued_interest);
    let supplier_rewards = accrued_interest.checked_sub(env, protocol_fee);

    (supplier_rewards, protocol_fee)
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

**File:** contracts/pool/src/interest.rs (L39-48)
```rust
fn accrue_chunk(env: &Env, cache: &mut Cache, delta_ms: u64) {
    let step = accrue_step(
        env,
        cache.params(),
        cache.borrowed(),
        cache.supplied(),
        cache.borrow_index(),
        cache.supply_index(),
        delta_ms,
    );
```

**File:** common/src/rates/scaling.rs (L12-16)
```rust
/// Converts a scaled `Ray` amount to its original (unscaled) value by
/// multiplying by `index`, rounding half up.
pub fn scaled_to_original(env: &Env, scaled: Ray, index: Ray) -> Ray {
    scaled.mul(env, index)
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

**File:** contracts/pool/src/ops/repay.rs (L40-45)
```rust
pub(crate) fn accounting(env: &Env, action: &PoolAction) -> RepayOutcome {
    let (mut cache, position) = ops::load_leg(env, action);
    let amount = action.amount;

    let (burned, overpayment) = cache.resolve_repay(amount, position);
    let net_repay = amount
```

**File:** contracts/pool/src/ops/recapitalize.rs (L44-52)
```rust
pub(crate) fn accounting(
    env: &Env,
    hub_asset: HubAssetKey,
    amount: i128,
) -> RecapitalizationOutcome {
    require_nonneg_amount(env, amount);
    let mut cache = ops::renewed_market(env, &hub_asset);

    let applied = amount.min(guards::backing_shortfall(&cache));
```

**File:** tests/test-harness/tests/controller/large_positions_and_long_horizons.rs (L321-343)
```rust
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
```

**File:** tests/test-harness/tests/controller/large_positions_and_long_horizons.rs (L347-356)
```rust
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

**File:** contracts/pool/src/lib.rs (L128-148)
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
```

**File:** contracts/pool/src/lib.rs (L174-180)
```rust
    /// Accrues interest for each market in `hub_assets` through the current
    /// ledger time. Commits state even with no elapsed time to reserve the write
    /// footprint, and emits its market state event. Restricted to the owner.
    #[only_owner]
    fn update_indexes(env: Env, hub_assets: Vec<HubAssetKey>) {
        ops::market::accrue(&env, hub_assets);
    }
```

**File:** contracts/pool/src/cache/scale.rs (L39-47)
```rust
    /// Converts an asset borrow into scaled debt shares (ceil at the borrow index).
    pub(crate) fn calculate_scaled_borrow(&self, amount: i128) -> Ray {
        calculate_scaled_borrow(
            &self.env,
            amount,
            self.params.asset_decimals,
            self.borrow_index,
        )
    }
```
