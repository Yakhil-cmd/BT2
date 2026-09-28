### Title
RAY value overflow permanently freezes an overgrown market - (File: common/src/rates/index.rs)

### Summary
A market whose scaled debt multiplied by its borrow index exceeds `i128::MAX` can no longer complete interest accrual. `calculate_supplier_rewards` multiplies the stored scaled debt by both the old and new borrow indexes, and the shared fixed-point helper panics when the resulting RAY value cannot fit in `i128` [1](#0-0) [2](#0-1) . Because every pool mutation syncs interest before applying its operation, this accrual failure blocks repayment, withdrawal, liquidation, and later index updates for that market [3](#0-2) [4](#0-3) .

### Finding Description
The protocol stores debt as RAY-scaled shares and derives its current value with `scaled * index / RAY`. The conversion helper delegates directly to `Ray::mul`, which panics on an unrepresentable `i128` result [5](#0-4) [6](#0-5) .

During accrual, `calculate_supplier_rewards` calculates both `borrowed * old_borrow_index` and `borrowed * new_borrow_index` [1](#0-0) . The borrow-index cap is applied only after `update_borrow_index` computes the index product, and it does not bound the separate `borrowed * index` value [7](#0-6) . Once the stored scaled debt is large enough, index growth can therefore cross the `i128` RAY-value ceiling before the index cap is reached.

The permissionless controller path calls `pool_update_indexes_call`, which invokes the pool's `update_indexes` entrypoint [8](#0-7) . The pool implementation loads each requested market and calls `interest::global_sync` before committing it [9](#0-8) . Every normal market mutation also calls `global_sync` through `synced_market` before its action runs [3](#0-2) .

The repository's own regression test demonstrates the reachable cliff: an 18-decimal market with one billion whole supplied units and 98% borrowed fails `update_indexes` with `MathOverflow` while still below `MAX_BORROW_INDEX_RAY`, after which withdrawal and repayment fail with the same error [10](#0-9) . The protocol documentation also acknowledges that accrued market values can exceed the RAY domain before the index ceiling and block repayment and withdrawal because they accrue first [11](#0-10) .

### Impact Explanation
This permanently freezes all supplier funds and borrower collateral associated with the affected market unless privileged code remediation is available. Suppliers cannot withdraw, borrowers cannot repay, and liquidators cannot execute the market-dependent liquidation path because each operation re-enters the same failing accrual step [3](#0-2) [12](#0-11) .

The impact is market-wide rather than limited to the attacker. All positions depending on the affected market lose access to withdrawals, repayments, liquidations, and further index synchronization.

### Likelihood Explanation
Exploitation requires a large listed market and sustained high utilization so that `scaled_debt * borrow_index / RAY` crosses `i128::MAX`. No privileged call, oracle manipulation, malicious token, or external integration is required: an unprivileged wallet can supply the debt asset to one owned account, supply collateral to another owned account, borrow at high utilization through `borrow`, and later call `update_indexes` as interest accrues [13](#0-12) [8](#0-7) .

The principal prerequisite is that governance-admitted supply and borrow caps permit the required exposure. The indexed regression test demonstrates the arithmetic condition and resulting freeze using only protocol operations and ledger-time advancement [10](#0-9) .

### Recommendation
Treat `scaled * index` overflow as a recoverable accrual boundary rather than an abortive arithmetic error:

- Bound stored scaled supply and debt so current market value cannot approach the `i128` RAY ceiling.
- Before applying index growth, calculate the implied new debt value in a wider integer and stop or clamp accrual before `calculate_supplier_rewards` performs an unrepresentable conversion.
- Add a recovery or settlement path that can process repayment and withdrawal without first requiring the overflowing aggregate accrual.
- Enforce operational caps below the arithmetic cliff, accounting for worst-case index growth rather than only entry-time token limits.
- Emit monitoring data when scaled market value approaches `i128::MAX` so governance can lower utilization before the market becomes unrecoverable.

### Proof of Concept
The existing test `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` is a direct executable proof [14](#0-13) :

1. Create an 18-decimal `BIG18` market and a separate collateral market.
2. As one unprivileged wallet controlling two accounts:
   - call `supply` for `BOB_ACCOUNT` with `[(BIG18, 1_000_000_000 * 10^18)]`;
   - call `supply` for `ALICE_ACCOUNT` with sufficient `COL`;
   - call `borrow` for `ALICE_ACCOUNT` with `[(BIG18, 980_000_000 * 10^18)]`.
3. Advance the ledger timestamp until the next accrual makes the debt's RAY value exceed `i128::MAX`.
4. Call `update_indexes(caller, [BIG18])`. The call reaches `global_sync`, then `calculate_supplier_rewards`, and aborts with `MathOverflow` while `borrow_index < MAX_BORROW_INDEX_RAY` [9](#0-8) [15](#0-14) [16](#0-15) .
5. Subsequent `withdraw` and `repay` calls fail with the same `MathOverflow` because they sync the market first [3](#0-2) [12](#0-11) .

### Citations

**File:** common/src/rates/index.rs (L13-18)
```rust
pub fn update_borrow_index(env: &Env, old_index: Ray, interest_factor: Ray) -> Ray {
    let new_index = old_index.mul(env, interest_factor);
    if new_index.raw() > MAX_BORROW_INDEX_RAY {
        return Ray::from(MAX_BORROW_INDEX_RAY);
    }
    new_index
```

**File:** common/src/rates/index.rs (L80-88)
```rust
    let old_total_debt = borrowed.mul(env, old_borrow_index);
    let new_total_debt = borrowed.mul(env, new_borrow_index);

    let accrued_interest = new_total_debt.checked_sub(env, old_total_debt);

    let protocol_fee = params.reserve_factor.apply_to_ray(env, accrued_interest);
    let supplier_rewards = accrued_interest.checked_sub(env, protocol_fee);

    (supplier_rewards, protocol_fee)
```

**File:** common/src/math/fp_core.rs (L108-118)
```rust
pub fn mul_div_half_up(env: &Env, x: i128, y: i128, d: i128) -> i128 {
    // The zero check runs first so debug and release builds agree on a zero
    // divisor: both surface `DivisionByZero` rather than tripping the assert.
    require_nonzero_divisor(env, d);
    debug_assert!(
        x >= 0 && y >= 0 && d > 0,
        "mul_div_half_up: non-negative x, y and positive d"
    );
    try_mul_div_half_up(env, x, y, d)
        .unwrap_or_else(|| panic_with_error!(env, GenericError::MathOverflow))
}
```

**File:** contracts/pool/src/ops/mod.rs (L29-40)
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
```

**File:** tests/test-harness/tests/controller/large_positions_and_long_horizons.rs (L315-360)
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
    std::println!(
        "ray-value cliff reached after {years} years at 98 percent utilization on the XLM curve; last index x{:.1}",
        last.borrow_index as f64 / RAY as f64
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

**File:** common/src/math/fp.rs (L49-52)
```rust
    /// Multiplies two ray values, rounding the result half up.
    pub fn mul(self, env: &Env, other: Ray) -> Ray {
        Ray(fp_core::mul_div_half_up(env, self.0, other.0, RAY))
    }
```

**File:** contracts/controller/src/external/pool.rs (L109-116)
```rust
/// Accrues and persists market indexes through the current ledger time.
pub(crate) fn pool_update_indexes_call(
    env: &Env,
    pool_addr: &Address,
    hub_assets: &Vec<HubAssetKey>,
) {
    LiquidityPoolClient::new(env, pool_addr).update_indexes(hub_assets)
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

**File:** docs/reference/formulas.md (L432-437)
```markdown
The token-to-RAY maximum is also the admitted cap maximum. Accrued position
values and market totals must independently fit the RAY domain; valid caps and
bounded indexes do not guarantee that future accrual fits. Value overflow can
occur before the index ceiling and block repayment/withdrawal because those
operations accrue first. At the borrow-index ceiling, further accrual produces
no borrower interest. No dedicated ceiling alarm is emitted.
```

**File:** contracts/controller/src/lib.rs (L94-115)
```rust
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
