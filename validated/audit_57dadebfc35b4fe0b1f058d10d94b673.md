### Title
Interest accrual overflows the i128 RAY-value domain and permanently freezes a market - (File: common/src/rates/simulate.rs)

### Summary
A sufficiently large, heavily utilized market can push `scaled_amount * index / RAY` beyond `i128::MAX`. `accrue_step` panics while valuing total supply or debt before the market timestamp is advanced, so every subsequent market operation repeats the same failing calculation and no user can withdraw, repay, liquidate, or clean up the market. [1](#0-0) [2](#0-1) 

### Finding Description
`global_sync` runs before each pool mutation and calls `accrue_step` for each elapsed accrual window. [3](#0-2)  `accrue_step` first computes `borrowed_original` and `supplied_original` using `scaled_to_original`. [4](#0-3)  `scaled_to_original` multiplies the scaled RAY amount by the index, and the fixed-point implementation returns `MathOverflow` when the exact `I256` result does not fit back into `i128`. [5](#0-4) [6](#0-5) 

The borrow and supply index caps do not prevent this condition because they constrain only the index, not the product of the stored share total and that index. [7](#0-6)  For example, an 18-decimal deposit of one billion whole tokens produces approximately `1e36` scaled RAY units; once the relevant index exceeds roughly `170x`, its aggregate value no longer fits in `i128`. [8](#0-7) 

Every normal mutation loads a synced cache through `load_leg`, so `supply`, `borrow`, `withdraw`, `repay`, `net_settle`, seizure, strategy creation, and liquidation-related pool calls all hit the same accrual first. [2](#0-1)  The permissionless controller `update_indexes` path also calls pool `update_indexes`, which runs `global_sync` and fails before `mark_accrued`, leaving `last_timestamp` old and making the overflow repeatable forever. [9](#0-8) [10](#0-9) 

### Impact Explanation
The result is permanent freezing of all supplier funds and all remaining pool liquidity in the affected `(hub_id, asset)` market. [11](#0-10)  Borrowers cannot repay, suppliers cannot withdraw, liquidators cannot operate on that market, and bad-debt cleanup cannot progress because the required pre-mutation accrual aborts first. [2](#0-1) [12](#0-11) 

This is demonstrated by the repository's own long-horizon test: once the RAY-value ceiling is reached, `update_indexes`, a withdrawal, and a repayment all revert with `MATH_OVERFLOW`, while the stored borrow index remains below its configured cap. [13](#0-12) 

### Likelihood Explanation
An unprivileged caller can establish the required state through `supply` and `borrow` on an existing listed market if its configured caps and token supply admit a sufficiently large aggregate. [14](#0-13)  The same caller can supply the borrowable asset, supply collateral in another asset, borrow up to the configured utilization limit, and later call permissionless `update_indexes`. [15](#0-14) 

The condition requires a very large balance, but no privileged action, oracle manipulation, leaked key, invalid parameter, or contract upgrade is required. [16](#0-15) [17](#0-16)  The harness reproduces the frozen state with ordinary controller operations followed only by ledger-time advancement and public index updates. [18](#0-17) 

### Recommendation
Enforce a value-domain ceiling as well as an index-domain ceiling during accrual. Before updating an index, derive the maximum index for the current `supplied` or `borrowed` share count as approximately `floor(i128::MAX * RAY / scaled_shares)`, then clamp the index to that bound before calling `scaled_to_original`. Alternatively, keep aggregate value and interest calculations in `I256` end-to-end and only convert to `i128` at token-unit boundaries where the final token amount is representable. The accrual path must still advance `last_timestamp` to a safe checkpoint or commit a bounded index, so a temporary extreme state cannot become an unrecoverable trap.

### Proof of Concept
For an existing 18-decimal market `H` and collateral market `C` whose caps admit the amounts:

```text
caller = attacker
principal = 1_000_000_000 * 10^18
debt      = principal * 95_00 / 10_000  // or the market's maximum allowed utilization

controller.supply(
    caller,
    account_id = 0,
    spoke_id = spoke,
    assets = [(H, principal)]
)

controller.supply(
    caller,
    account_id = collateral_account,
    spoke_id = spoke,
    assets = [(C, sufficient_collateral)]
)

controller.borrow(
    caller,
    account_id = collateral_account,
    borrows = [(H, debt)],
    to = Some(caller)
)
```

After ledger time advances enough for the borrow or supply value to exceed `i128::MAX`, submit:

```text
controller.update_indexes(caller, assets = [H])
```

`pool.update_indexes` loads `H`, calls `global_sync`, and panics inside `accrue_step` before `mark_accrued`. [10](#0-9) [1](#0-0)  Subsequent `withdraw`, `repay`, `liquidate`, or `clean_bad_debt` transactions touching `H` repeat the same panic because they call `load_leg` and therefore `global_sync` before performing their own mutation. [19](#0-18)  The checked-in regression `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` demonstrates this exact sequence and resulting permanent `MATH_OVERFLOW` failures. [20](#0-19)

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

**File:** common/src/rates/scaling.rs (L12-16)
```rust
/// Converts a scaled `Ray` amount to its original (unscaled) value by
/// multiplying by `index`, rounding half up.
pub fn scaled_to_original(env: &Env, scaled: Ray, index: Ray) -> Ray {
    scaled.mul(env, index)
}
```

**File:** common/src/math/fp_core.rs (L138-143)
```rust
    let (x256, y256, d256) = to_i256_operands(env, x, y, d);
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

**File:** tests/test-harness/tests/controller/large_positions_and_long_horizons.rs (L315-320)
```rust
/// The cliff. A billion whole tokens is `1e36` raw ray; the value ceiling is
/// `i128::MAX`, 170 times that. At the XLM curve's steep segment the index
/// grows past 170x in a few years, and the next accrual panics inside
/// `scaled_to_original`. Every verb accrues first, so the market freezes:
/// no repay, no withdraw, no liquidation. The index cap never engages.
#[test]
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

**File:** contracts/pool/src/ops/market.rs (L65-72)
```rust
pub(crate) fn accrue(env: &Env, hub_assets: Vec<HubAssetKey>) {
    renew_instance(env);

    for hub_asset in hub_assets.iter() {
        let mut cache = Cache::load(env, &hub_asset);
        interest::global_sync(env, &mut cache);
        events::emit_market_state(env, cache.commit());
    }
```

**File:** contracts/pool/src/cache/mod.rs (L73-85)
```rust
    /// Persists the full market state and returns a snapshot for events.
    pub(crate) fn commit(&self) -> MarketStateSnapshot {
        let state = PoolStateRaw {
            supplied: self.supplied.raw(),
            borrowed: self.borrowed.raw(),
            revenue: self.revenue.raw(),
            borrow_index: self.borrow_index.raw(),
            supply_index: self.supply_index.raw(),
            last_timestamp: self.last_timestamp,
            cash: self.cash,
        };
        storage::write_state(&self.env, &self.hub_asset, &state);
        self.snapshot()
```

**File:** contracts/pool/src/ops/borrow.rs (L42-49)
```rust
pub(crate) fn accounting(env: &Env, entry: &PoolBorrowEntry) -> BorrowOutcome {
    let (mut cache, mut position) = ops::load_leg(env, &entry.action);
    let amount = entry.action.amount;

    mint_debt(env, &mut cache, &mut position, amount);
    cache.debit_cash(amount);

    let snapshot = cache.commit();
```

**File:** contracts/pool/src/ops/borrow.rs (L63-79)
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
}
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

**File:** contracts/controller/src/lib.rs (L367-372)
```rust
    /// Accrues pool borrow and supply indexes for `assets`. Permissionless;
    /// requires caller authorization.
    #[when_not_paused]
    fn update_indexes(env: Env, caller: Address, assets: Vec<HubAssetKey>) {
        markets::update_indexes(&env, caller, assets);
    }
```

**File:** contracts/controller/src/positions/supply.rs (L115-133)
```rust
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
    }

    let results = pool_supply_call(env, &pool_addr, &entries);
    for_each_leg(env, &entries, &results, |entry, result| {
```
