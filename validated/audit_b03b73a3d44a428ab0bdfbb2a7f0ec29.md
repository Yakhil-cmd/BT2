### Title
Unchecked interest-accrual value overflow permanently freezes an oversized market - (File: contracts/pool/src/interest.rs)

### Summary
A market whose scaled debt is large enough can reach a state where the next interest-accrual calculation overflows `i128` before the borrow-index ceiling can clamp growth. Because every pool mutation synchronizes the market before applying its operation, `withdraw`, `repay`, `liquidate`, `clean_bad_debt`, `recapitalize`, and `update_indexes` all revert thereafter. This permanently locks supplier cash and prevents debt repayment or liquidation for that market.

### Finding Description
`interest::global_sync` always runs before a pool mutation and calls `accrue_chunk` for each elapsed chunk [1](#0-0) . `accrue_chunk` calls `accrue_step` and writes the resulting borrow and supply indexes back to the market cache [2](#0-1) .

The borrow index itself is capped only after `old_index * interest_factor` is calculated [3](#0-2) . More importantly, `calculate_supplier_rewards` then multiplies the total scaled debt by both the old and new indexes to derive total debt and accrued interest [4](#0-3) . These scaled-to-original conversions delegate to `scaled.mul(index)` without a recovery path [5](#0-4) .

The pool’s shared `synced_market` helper invokes this accrual before returning the cache [6](#0-5) , and withdrawal and repayment legs both enter accounting through that synchronized cache [7](#0-6) [8](#0-7) . `update_indexes` likewise calls the market accrual operation directly [9](#0-8) .

The borrow-index ceiling is `10^36` raw RAY, but it does not guarantee that `scaled_debt * index` remains representable in `i128` [10](#0-9) . Therefore, an oversized market can cross the finite RAY-value capacity before reaching the configured index ceiling.

### Impact Explanation
Once `borrowed * borrow_index` or `borrowed * new_borrow_index` exceeds `i128::MAX`, the accrual call panics. Since synchronization is a precondition for the affected market’s mutation paths, the market cannot process withdrawals, repayments, borrows, liquidations, bad-debt cleanup, recapitalization, or index updates. Suppliers’ underlying pool cash remains locked even though risk-reducing operations such as repayment and liquidation should ordinarily remain available.

This is not merely an unavailable convenience endpoint: the state transition required to unscale and mutate every market position is the same transition that traps. No caller-supplied amount can skip `global_sync`, so the failed multiplication cannot be avoided by choosing a smaller withdrawal or repayment.

### Likelihood Explanation
The attack path is permissionless but economically demanding. An attacker can create an ordinary account through `Controller::supply` and `Controller::borrow`, drive utilization high with a very large debt position, and leave the market to compound until the scaled-debt multiplication overflows [11](#0-10) .

Likelihood is constrained by governance-configured asset supply and borrow caps, available collateral, liquidity, interest-rate parameters, and the amount of elapsed accrual required. Nevertheless, the protocol explicitly permits large but finite positions governed by literal caps, and the tested scenario demonstrates that the market can hit the `i128` value ceiling while its borrow index remains below `MAX_BORROW_INDEX_RAY` [12](#0-11) .

### Recommendation
Make accrual value-safe instead of relying on the index cap alone:

1. Compute total debt with checked `i256`-style or widened intermediate arithmetic before converting back to `i128`.
2. Detect the first accrual chunk whose resulting total debt cannot be represented, and either clamp accrual safely at the largest representable market state or enter an explicit market recovery mode.
3. Allow risk-reducing operations—at minimum repayment, liquidation, bad-debt cleanup, recapitalization, and withdrawal—to execute against the last safely represented state rather than unconditionally trapping in `global_sync`.
4. Enforce entry-side bounds so `scaled_debt * MAX_BORROW_INDEX_RAY` cannot exceed the protocol’s representable value domain, accounting for asset decimals and future index growth.
5. Add a regression test proving that repayment and withdrawal remain possible after the borrow index approaches or reaches its ceiling.

### Proof of Concept
The repository already contains a concrete harness reproduction in `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs`. It creates a very large 18-decimal market, supplies `1e27` base units, borrows 98% of that amount, advances ledger time, and invokes `try_update_indexes_for(&["BIG18"])` until the call returns `MATH_OVERFLOW` [13](#0-12) .

After the overflow, the same test verifies that the stored borrow index remains below `MAX_BORROW_INDEX_RAY`, while both `withdraw` and `repay` still fail with `MATH_OVERFLOW` because those operations accrue first [14](#0-13) . This directly demonstrates the permanent market-freeze condition and the inability of even risk-reducing callers to recover the market.

### Citations

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

**File:** contracts/pool/src/interest.rs (L39-52)
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

    cache.set_borrow_index(step.borrow_index);
    cache.set_supply_index(step.supply_index);
    cache.accrue_revenue(step.revenue_shares);
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

**File:** common/src/rates/scaling.rs (L12-16)
```rust
/// Converts a scaled `Ray` amount to its original (unscaled) value by
/// multiplying by `index`, rounding half up.
pub fn scaled_to_original(env: &Env, scaled: Ray, index: Ray) -> Ray {
    scaled.mul(env, index)
}
```

**File:** contracts/pool/src/ops/mod.rs (L29-34)
```rust
/// Loads a market cache and accrues interest through the current ledger time.
pub(crate) fn synced_market(env: &Env, hub_asset: &HubAssetKey) -> Cache {
    let mut cache = Cache::load(env, hub_asset);
    interest::global_sync(env, &mut cache);
    cache
}
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

**File:** contracts/pool/src/ops/repay.rs (L36-44)
```rust
/// Accrues interest, resolves the repay amount into burned debt shares and
/// overpayment, burns the shares, and credits the net repay to cash without
/// transferring the overpayment refund. Panics if a positive net repay would
/// burn zero scaled shares.
pub(crate) fn accounting(env: &Env, action: &PoolAction) -> RepayOutcome {
    let (mut cache, position) = ops::load_leg(env, action);
    let amount = action.amount;

    let (burned, overpayment) = cache.resolve_repay(amount, position);
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

**File:** common/src/constants/pool.rs (L18-23)
```rust
/// Ceiling the borrow index is clamped to after growth, in raw ray units.
pub const MAX_BORROW_INDEX_RAY: i128 = 1_000_000_000_000_000_000_000_000_000_000_000_000;

/// Ceiling the supply index is clamped to after growth, in raw ray units.
/// Equal to [`MAX_BORROW_INDEX_RAY`].
pub const MAX_SUPPLY_INDEX_RAY: i128 = MAX_BORROW_INDEX_RAY;
```

**File:** contracts/controller/src/lib.rs (L90-115)
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
    }
```

**File:** tests/test-harness/tests/controller/large_positions_and_long_horizons.rs (L316-356)
```rust
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
