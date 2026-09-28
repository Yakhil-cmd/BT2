### Title
RAY-value overflow during accrual permanently freezes an overgrown market - ([File: common/src/rates/simulate.rs])

### Summary
A large market can reach a state in which `scaled shares * index` exceeds `i128::MAX` before either index reaches its configured cap. The next accrual panics in `scaled_to_original`, and because all mutating market operations load an interest-synced cache first, repayment, withdrawal, liquidation, and every other operation touching that market subsequently fail. [1](#0-0) 

### Finding Description
`accrue_step` first expands `borrowed` and `supplied` scaled RAY balances through `scaled_to_original`, which delegates to `Ray::mul`. [2](#0-1)  `scaled_to_original` performs the index multiplication directly rather than saturating or applying the index ceiling first. [3](#0-2)  `Ray::mul` calls `mul_div_half_up`, which raises `MathOverflow` when the exact result does not fit in `i128`. [4](#0-3) 

The borrow-index cap is applied only after the product needed to calculate the new index is computed, and supplier rewards then calculate old and new total debt with additional index multiplications. [5](#0-4) [6](#0-5)  Consequently, the representable RAY value of the scaled position can overflow before `MAX_BORROW_INDEX_RAY` or `MAX_SUPPLY_INDEX_RAY` is reached. [7](#0-6) 

Every market mutation invokes `synced_market`, which loads the cache and calls `global_sync`; `global_sync` runs `accrue_chunk`, and `accrue_chunk` invokes `accrue_step`. [8](#0-7) [9](#0-8)  The pool's supply, borrow, withdraw, repay, liquidation seizure, and index-update paths all use this accrual sequence. [10](#0-9) [11](#0-10) 

An unprivileged borrower can reach the vulnerable path through controller `borrow` to place a sufficiently large market at sustained high utilization, followed by controller `update_indexes`, which forwards to the pool's accrual entrypoint. [12](#0-11) [13](#0-12) 

### Impact Explanation
Once the state crosses the representable-value boundary, every transaction that touches the market traps while trying to accrue rather than merely rejecting the caller's requested action. Suppliers cannot withdraw, borrowers cannot repay, liquidators cannot clear positions, and keepers cannot update the market, so market funds become permanently frozen absent a privileged state repair or upgrade. [14](#0-13) 

The checked arithmetic prevents corrupted balances, but it converts a reachable accounting limit into a market-wide liveness failure. This is analogous to the reported memory-overflow denial of service: a large crafted state causes processing to fail before the protocol can apply its intended index bound. [15](#0-14) 

### Likelihood Explanation
The attack requires an exceptionally large market and enough collateral for a borrow that drives high utilization, but it requires no privileged role or malformed authorization. The repository's regression test constructs a one-billion-whole-token, 18-decimal market, borrows 98% of it, and demonstrates that `update_indexes` reaches `MathOverflow` while the borrow index remains below its cap. [16](#0-15) 

The substantial capital requirement and dependence on sustained high-utilization accrual limit practical exploitability, supporting Medium severity rather than Critical or High. [17](#0-16) 

### Recommendation
Before unscaling `borrowed` or `supplied`, detect whether the exact value would exceed `i128` and transition the market into an explicit terminal accrual mode that clamps the index or disables further interest without reverting. Alternatively, cap the scaled balance or index product before `Ray::mul`, and add an emergency state path that lets repayment, liquidation, and withdrawal operate at the capped accounting state. A regression test should prove that `update_indexes`, `repay`, `withdraw`, and liquidation continue to execute at the first state where the exact RAY value would otherwise overflow.

### Proof of Concept
1. Configure an 18-decimal market with a steep rate curve and effectively permissive utilization/cap limits, plus a collateral market. [17](#0-16) 
2. Supply `1_000_000_000 * 10^18` units of the debt asset to the target market. [18](#0-17) 
3. With sufficient collateral in the second market, call controller `borrow` for 98% of the supplied debt asset. [19](#0-18) 
4. Advance ledger time across successive accrual intervals and call controller `update_indexes` for the debt asset until `accrue_step` attempts `scaled_to_original(borrowed, borrow_index)` with a result above `i128::MAX`. [1](#0-0) 
5. The repository's test observes `MathOverflow` from `update_indexes`, then observes the same error from `withdraw` and `repay`, demonstrating that the first panic makes the market permanently inaccessible through its normal recovery paths. [20](#0-19)

### Citations

**File:** common/src/rates/simulate.rs (L51-69)
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

**File:** common/src/rates/scaling.rs (L12-16)
```rust
/// Converts a scaled `Ray` amount to its original (unscaled) value by
/// multiplying by `index`, rounding half up.
pub fn scaled_to_original(env: &Env, scaled: Ray, index: Ray) -> Ray {
    scaled.mul(env, index)
}
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

**File:** common/src/rates/index.rs (L73-83)
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

**File:** contracts/pool/src/ops/mod.rs (L29-34)
```rust
/// Loads a market cache and accrues interest through the current ledger time.
pub(crate) fn synced_market(env: &Env, hub_asset: &HubAssetKey) -> Cache {
    let mut cache = Cache::load(env, hub_asset);
    interest::global_sync(env, &mut cache);
    cache
}
```

**File:** contracts/pool/src/interest.rs (L20-40)
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

/// Applies one compound step of `delta_ms` to indexes and protocol revenue.
///
/// The arithmetic lives in [`accrue_step`], shared with the read-only
/// `simulate_update_indexes` so the view and the mutator cannot drift.
fn accrue_chunk(env: &Env, cache: &mut Cache, delta_ms: u64) {
    let step = accrue_step(
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

**File:** contracts/pool/src/lib.rs (L224-230)
```rust
    /// Seizes positions during liquidation or bad-debt cleanup. Borrow-side
    /// entries socialize bad debt onto the supply index and burn the debt;
    /// deposit-side entries reclassify supply shares as protocol revenue.
    /// Restricted to the owner.
    #[only_owner]
    fn seize_positions(env: Env, entries: Vec<PoolSeizeEntry>) {
        ops::run_batch(&env, entries, |e, entry| ((), ops::seize::apply(e, entry)));
```

**File:** docs/reference/endpoints.md (L24-38)
```markdown
| `supply(caller: Address, account_id: u64, spoke_id: u32, assets: Vec<(HubAssetKey, i128)>) -> u64` | Existing assets only for third parties | gated | Supply measured deposits; id 0 creates Normal account. |
| `borrow(caller: Address, account_id: u64, borrows: Vec<(HubAssetKey, i128)>, to: Option<Address>)` | NFT owner/delegate | gated | Debt booked to account; recipient defaults to caller. |
| `withdraw(caller: Address, account_id: u64, withdrawals: Vec<(HubAssetKey, i128)>, to: Option<Address>) -> Vec<(HubAssetKey, i128)>` | NFT owner/delegate | open | Zero means full withdrawal; returns the amounts paid. |
| `repay(caller: Address, account_id: u64, payments: Vec<(HubAssetKey, i128)>)` | None | open | Anyone can repay; excess returns to caller. |
| `liquidate(liquidator: Address, account_id: u64, debt_payments: Vec<(HubAssetKey, i128)>, seize_mode: SeizeMode) -> u64` | None; credit receiver owner/delegate | open | Pro-rata seizure; Transfer returns 0, Credit returns receiver id. |
| `clean_bad_debt(caller: Address, account_id: u64)` | None | open | Debt exceeds collateral and collateral <= $5; socialize and burn NFT. |
| `flash_loan(caller: Address, asset: HubAssetKey, amount: i128, receiver: Address, data: Bytes)` | None | gated | Wasm callback; pool pulls exact principal plus fee. |
| `flash_position(caller: Address, account_id: u64, spoke_id: u32, mode: PositionMode, debt: HubAssetKey, amount: i128, receiver: Address, data: Bytes, collaterals: Vec<(HubAssetKey, i128)>, refund_assets: Vec<Address>) -> u64` | NFT owner/delegate for existing id | gated | Mint fee-free debt; deposit declared collateral that the callback delivers. |
| `multiply(caller: Address, account_id: u64, spoke_id: u32, collateral: HubAssetKey, debt_to_flash_loan: i128, debt: HubAssetKey, mode: PositionMode, swap: Bytes, initial_payment: Option<(HubAssetKey, i128)>, convert_swap: Option<Bytes>) -> u64` | NFT owner/delegate for existing id | gated | Borrow, swap and supply; optional initial capital. |
| `swap_debt(caller: Address, account_id: u64, existing_debt: HubAssetKey, amount: i128, new_debt: HubAssetKey, swap: Bytes)` | NFT owner/delegate | gated | Borrow new debt, then repay existing debt with the swap output. The new borrow must fit its borrow cap and the borrow-position limit before repayment. |
| `swap_collateral(caller: Address, account_id: u64, current: HubAssetKey, amount: i128, new: HubAssetKey, swap: Bytes)` | NFT owner/delegate | gated | Withdraw, convert and redeposit collateral. |
| `repay_debt_with_collateral(caller: Address, account_id: u64, collateral: HubAssetKey, collateral_amount: i128, debt: HubAssetKey, swap: Bytes, close_position: bool)` | NFT owner/delegate | gated | Direct same-market netting or swap; optional full close. |
| `migrate_from_blend(caller: Address, account_id: u64, spoke_id: u32, hub_id: u32, blend_pool: Address, collateral_assets: Vec<Address>, supply_assets: Vec<Address>, debt_caps: Vec<(Address, i128)>) -> u64` | NFT owner/delegate for existing id | gated | Migrate caller’s position from approved Blend pool. |
| `update_indexes(caller: Address, assets: Vec<HubAssetKey>)` | None | gated | Accrue specified markets. |
| `claim_revenue(caller: Address, assets: Vec<HubAssetKey>) -> Vec<i128>` | None | gated | Pay only configured accumulator; return controller receipts. |
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

**File:** tests/test-harness/tests/controller/large_positions_and_long_horizons.rs (L321-356)
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

**File:** common/src/math/fp_core.rs (L120-143)
```rust
/// Computes `x * y / d` rounded half up. Returns `None` if `x < 0`, `y < 0`, `d <= 0`, or the
/// result does not fit in `i128`.
pub fn try_mul_div_half_up(env: &Env, x: i128, y: i128, d: i128) -> Option<i128> {
    if x < 0 || y < 0 || d <= 0 {
        return None;
    }
    let half = d / 2;

    // Fast path: the biased product fits `i128`, so the whole computation is
    // native. `x * y + half` is non-negative here, so `/` is the floor the
    // widened path would produce.
    if let Some(biased) = x
        .checked_mul(y)
        .and_then(|product| product.checked_add(half))
    {
        return Some(biased / d);
    }

    let (x256, y256, d256) = to_i256_operands(env, x, y, d);
    x256.mul(&y256)
        .add(&I256::from_i128(env, half))
        .div(&d256)
        .to_i128()
}
```
