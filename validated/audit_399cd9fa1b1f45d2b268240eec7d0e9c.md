### Title
Accrual arithmetic overflow permanently freezes an oversized high-utilization market - ([File: common/src/rates/simulate.rs])

### Summary
`accrue_step` converts aggregate scaled debt and supply to unscaled values before calculating utilization. These conversions are bounded only by `i128`, while the admitted token-domain cap can allow a scaled balance large enough that `scaled * index` overflows well before `MAX_BORROW_INDEX_RAY` engages. After that point, every pool operation first calls `global_sync`, so repayments, withdrawals, liquidations, bad-debt cleanup, and further index updates all revert. [1](#0-0) [2](#0-1) 

### Finding Description
`scaled_to_original` performs `scaled.mul(index)` without a saturation or widened-value fallback. [3](#0-2)  The accrual loop calls it once for borrowed shares and once for supplied shares before it computes utilization and the next indexes. [4](#0-3)  Although `update_borrow_index` caps the resulting index at `MAX_BORROW_INDEX_RAY`, the cap is applied only after `old_index.mul(interest_factor)`; separately, `calculate_supplier_rewards` multiplies `borrowed` by both old and new indexes. [5](#0-4) [6](#0-5) 

The controller exposes this state transition through permissionless `update_indexes(caller, assets)`, which forwards the selected `HubAssetKey` list to the pool. [7](#0-6) [8](#0-7)  All ordinary pool legs also load an interest-synced market, so the first overflowing conversion prevents the operation from reaching its repayment, withdrawal, or seizure logic. [9](#0-8) 

### Impact Explanation
Once aggregate scaled debt multiplied by the borrow index no longer fits in `i128`, the market cannot accrue. Because every subsequent pool mutation accrues first, suppliers cannot withdraw, borrowers cannot repay, liquidators cannot repay that debt market, and bad-debt cleanup or recapitalization cannot recover the market. The result is permanent freezing of user funds and unclaimed yield absent a contract upgrade or migration. [10](#0-9) [11](#0-10) 

### Likelihood Explanation
Likelihood is Medium. An unprivileged account can reach this state by supplying enough of a high-decimal asset, posting collateral in another admitted market, borrowing at sustained high utilization, and letting interest accrue until the fixed-point ceiling is crossed. The required liquidity is extreme—on the order of a billion whole 18-decimal tokens in the demonstrated configuration—and market caps must admit that exposure, so ordinary configured markets may not be exploitable. Within an admitted oversized market, however, no privileged call or oracle manipulation is needed because `supply`, `borrow`, and `update_indexes` are reachable through the controller. [12](#0-11) [13](#0-12) 

### Recommendation
Enforce an accrual-safe bound when minting supply or debt shares: the stored scaled aggregate must remain representable at `MAX_BORROW_INDEX_RAY` and `MAX_SUPPLY_INDEX_RAY`, not merely at the current index. Alternatively, represent aggregate debt and supply values with `I256` throughout utilization, interest, withdrawal, repayment, liquidation, and bad-debt paths, and only convert back after proving the result fits `i128`. Add regression tests showing that repayment and withdrawal remain possible after an index approaches its protocol cap. [5](#0-4) [14](#0-13) 

### Proof of Concept
1. Configure or identify an 18-decimal market whose supply and borrow caps admit approximately `1_000_000_000 * 10^18` base units.
2. Attacker calls `supply` with that amount, supplies sufficient collateral in a second market, then calls `borrow` for approximately 98% of the first market’s liquidity.
3. Leave the market at sustained high utilization and periodically call permissionless `update_indexes` for its `HubAssetKey`.
4. When the borrow index has grown enough that `borrowed_scaled_ray * borrow_index_ray / RAY` exceeds `i128::MAX`, `accrue_step` panics at its `scaled_to_original` call.
5. Subsequent `update_indexes`, `repay`, `withdraw`, and liquidation attempts all fail before state mutation because they load a synced market.

The repository’s regression test demonstrates this sequence: it creates the oversized 18-decimal market, borrows 98%, advances time until `update_indexes` returns `MathOverflow`, and then observes that both withdrawal and repayment fail with the same error. [15](#0-14)

### Citations

**File:** common/src/rates/simulate.rs (L51-72)
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

    let new_supply_index = update_supply_index(env, supplied, supply_index, supplier_rewards);
    let supplier_shortfall = supply_index_reward_shortfall(
```

**File:** contracts/pool/src/ops/mod.rs (L29-47)
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

**File:** common/src/rates/index.rs (L13-18)
```rust
pub fn update_borrow_index(env: &Env, old_index: Ray, interest_factor: Ray) -> Ray {
    let new_index = old_index.mul(env, interest_factor);
    if new_index.raw() > MAX_BORROW_INDEX_RAY {
        return Ray::from(MAX_BORROW_INDEX_RAY);
    }
    new_index
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

**File:** tests/test-harness/tests/controller/large_positions_and_long_horizons.rs (L321-357)
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
    std::println!(
```

**File:** docs/reference/formulas.md (L429-437)
```markdown
| Token-to-RAY input maximum `i128::MAX / 10^(27-d)` | About 170.14 billion whole tokens, before other limits |
| Deposit conversion at the supply-index floor | About 170.14 million whole tokens before scaled-share overflow |

The token-to-RAY maximum is also the admitted cap maximum. Accrued position
values and market totals must independently fit the RAY domain; valid caps and
bounded indexes do not guarantee that future accrual fits. Value overflow can
occur before the index ceiling and block repayment/withdrawal because those
operations accrue first. At the borrow-index ceiling, further accrual produces
no borrower interest. No dedicated ceiling alarm is emitted.
```
