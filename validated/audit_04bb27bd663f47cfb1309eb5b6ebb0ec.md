### Title
RAY-valued debt overflow permanently freezes a saturated market - ([File: `contracts/pool/src/cache/scale.rs`])

### Summary
The pool computes total debt as `borrowed_scaled * borrow_index` inside `Cache::calculate_utilization`, without first bounding the resulting RAY-valued amount to `i128`. [1](#0-0) 

If scaled debt is large enough that a subsequent index increase makes this product exceed `i128::MAX`, interest accrual panics with `MathOverflow` before the configured borrow-index cap can take effect. [2](#0-1) 

Because pool entrypoints accrue interest before supply, borrow, repayment, withdrawal, liquidation seizure, and explicit index updates, the affected market becomes permanently unusable. [3](#0-2) 

### Finding Description
`LiquidityPool::update_indexes` delegates to `ops::market::accrue`, while the other mutating pool entrypoints likewise run their accrual path before applying the requested operation. [3](#0-2) 

Accrual invokes `global_sync`, which applies compound chunks through `accrue_chunk`. [4](#0-3) 

The overflow point is the market's utilization calculation: `calculate_utilization` calls `scaled_to_original` on both stored scaled debt and the current borrow index before computing utilization. [1](#0-0) 

A regression test demonstrates that a very large 18-decimal market at sustained high utilization reaches this ceiling while the stored borrow index remains below `MAX_BORROW_INDEX_RAY`, then both withdrawal and repayment revert with `MATH_OVERFLOW`. [2](#0-1) 

The permissionless controller-facing trigger is `Controller::update_indexes(caller, assets)`, which forwards the selected `HubAssetKey` list to `pool_update_indexes_call`. [5](#0-4) [6](#0-5) 

### Impact Explanation
Once the state reaches the overflow boundary, the stored scaled debt and borrow index make every later accrual attempt overflow before state is committed. [4](#0-3) 

This permanently freezes supplier principal, accrued yield, borrower repayment, collateral withdrawal involving the market, liquidation of debt in that market, and protocol-revenue operations that need to sync the market. [3](#0-2) 

The impact is stronger than a temporary fail-closed revert because no unprivileged or ordinary pool operation can advance the market past the poisonous index state, and the regression test explicitly confirms repayment and withdrawal remain blocked. [7](#0-6) 

### Likelihood Explanation
Triggering the bug requires an admitted market whose scaled debt and index growth can produce a RAY-valued debt above `i128::MAX`. [1](#0-0) 

The repository's own test constructs this state with `1e27` units of an 18-decimal asset borrowed at approximately 98% utilization and advances time until accrual fails. [8](#0-7) 

That makes the practical likelihood dependent on asset decimals, configured caps, available token supply, rate model, and sustained utilization; however, the final panic itself can be triggered by any authenticated caller through `update_indexes`, and normal user operations later hit the same state organically. [6](#0-5) 

### Recommendation
Compute utilization using a checked or widened product and treat an overflowing debt valuation as saturated rather than panicking. [1](#0-0) 

The borrow-index ceiling must be enforced before converting scaled debt back to a RAY asset value, or accrual should short-circuit when the stored index reaches `MAX_BORROW_INDEX_RAY`. [9](#0-8) 

If full-precision utilization is unnecessary at that boundary, cap total borrowed value at `i128::MAX` for rate calculations while preserving exact share-based accounting for withdrawals and repayments. [10](#0-9) 

### Proof of Concept
1. Configure a listed 18-decimal market with a sufficiently large supply and borrow cap, plus a collateral market permitting approximately 98% utilization.
2. Through `Controller::supply`, supply `1_000_000_000 * 10^18` base units of the debt asset.
3. Through `Controller::supply`, create or fund collateral sufficient to borrow `98%` of that market.
4. Through `Controller::borrow`, borrow `980_000_000 * 10^18` base units.
5. Advance ledger time until `scaled_debt * borrow_index` would exceed `i128::MAX`.
6. Call `Controller::update_indexes(caller, vec![debt_asset])`.

The final call reverts with `MathOverflow`; subsequent `withdraw` and `repay` calls for that market revert identically, matching the checked-in reproduction. [11](#0-10)

### Citations

**File:** contracts/pool/src/cache/scale.rs (L19-27)
```rust
    pub(crate) fn calculate_utilization(&self) -> Ray {
        if self.supplied == Ray::ZERO {
            return Ray::ZERO;
        }
        let total_borrowed = scaled_to_original(&self.env, self.borrowed, self.borrow_index);
        let total_supplied = scaled_to_original(&self.env, self.supplied, self.supply_index);

        utilization(&self.env, total_borrowed, total_supplied)
    }
```

**File:** contracts/pool/src/cache/scale.rs (L69-92)
```rust
    /// Unscales debt shares to asset units with half-up rounding.
    pub(crate) fn unscale_borrow(&self, scaled: Ray) -> i128 {
        unscale_borrow(
            &self.env,
            scaled,
            self.borrow_index,
            self.params.asset_decimals,
        )
    }

    /// Unscales debt shares rounding **up** (conservative liability).
    pub(crate) fn unscale_borrow_ceil(&self, scaled: Ray) -> i128 {
        unscale_borrow_ceil(
            &self.env,
            scaled,
            self.borrow_index,
            self.params.asset_decimals,
        )
    }

    /// Unscales debt shares to a RAY asset amount, rounding up.
    pub(crate) fn unscale_borrow_ceil_ray(&self, scaled: Ray) -> Ray {
        scaled.mul_ceil(&self.env, self.borrow_index)
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

**File:** contracts/pool/src/lib.rs (L128-180)
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
```

**File:** contracts/pool/src/interest.rs (L20-33)
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
}
```

**File:** contracts/pool/src/interest.rs (L35-53)
```rust
/// Applies one compound step of `delta_ms` to indexes and protocol revenue.
///
/// The arithmetic lives in [`accrue_step`], shared with the read-only
/// `simulate_update_indexes` so the view and the mutator cannot drift.
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
}
```

**File:** contracts/controller/src/lib.rs (L367-372)
```rust
    /// Accrues pool borrow and supply indexes for `assets`. Permissionless;
    /// requires caller authorization.
    #[when_not_paused]
    fn update_indexes(env: Env, caller: Address, assets: Vec<HubAssetKey>) {
        markets::update_indexes(&env, caller, assets);
    }
```

**File:** contracts/controller/src/markets.rs (L118-125)
```rust
/// Accrues indexes for each hub asset. Requires caller authorization and no flash loan.
pub(crate) fn update_indexes(env: &Env, caller: Address, assets: Vec<HubAssetKey>) {
    validation::require_authorized_caller(env, &caller);

    let mut cache = Context::new(env);
    let pool_addr = cache.cached_pool_address();
    pool_update_indexes_call(env, &pool_addr, &assets);
}
```
