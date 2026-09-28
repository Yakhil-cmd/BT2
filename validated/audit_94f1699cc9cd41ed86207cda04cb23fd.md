### Title
RAY-value overflow during interest accrual permanently freezes pool operations - ([File: common/src/math/fp_core.rs])

### Summary
An unprivileged user can drive a sufficiently large, highly utilized market past the `i128` RAY-value ceiling, after which interest accrual panics with `MathOverflow`. Because every pool mutation performs accrual before processing, repayment, withdrawal, liquidation, and index updates for that market subsequently become unusable, permanently freezing its funds. [1](#0-0) [2](#0-1) 

### Finding Description
Token amounts are converted into RAY shares with `Ray::from_asset`, while their current value is reconstructed as `scaled * index / RAY`. [3](#0-2) [4](#0-3) 

The configured asset cap only proves that the original token amount can be upscaled into RAY; it does not prove that the accrued share value remains representable. The documentation explicitly notes that accrued position values and market totals must independently fit the RAY domain and that value overflow can block repayment and withdrawal. [5](#0-4) [6](#0-5) 

During accrual, `Cache::calculate_utilization` multiplies total borrowed and total supplied shares by their indexes. [7](#0-6)  The product is evaluated safely through `I256`, but conversion of a result larger than `i128::MAX` returns `None` and is converted into a `MathOverflow` panic. [8](#0-7) [9](#0-8) 

Withdrawal cannot bypass this state by requesting a smaller amount because `resolve_withdrawal` first unscales the entire position twice—once half-up and once floor—before deciding whether the request is partial or full. [10](#0-9)  The resulting value is then burned and paid through the normal withdraw accounting path. [11](#0-10) 

### Impact Explanation
This causes permanent freezing of funds and makes the affected market unable to operate. Suppliers cannot withdraw, borrowers cannot repay, liquidations cannot be executed, and `update_indexes` cannot commit once the accrued market value exceeds `i128::MAX`. [2](#0-1) 

The impact is broader than the rejected oversized-input case tested at supply entry: an originally valid deposit can become inaccessible solely because later interest makes its value unrepresentable. [12](#0-11) [6](#0-5) 

### Likelihood Explanation
The scenario requires a whale-scale market and sustained high utilization under a steep rate curve, so it is not reachable with ordinary balances or parameters. However, the required deposit is within the protocol’s admitted cap domain—about 170 billion whole tokens rather than an unrepresentable `u256`-style input—and the user-facing supply and borrow paths are permissionless once such market configuration exists. [5](#0-4) [13](#0-12) 

The checked-in stress test demonstrates the concrete cliff: one billion 18-decimal tokens at approximately 98% utilization on the steep XLM curve eventually makes accrual revert before the configured index ceiling is reached, and subsequent withdraw and repay calls also revert. [14](#0-13) 

### Recommendation
Market totals and position values that can grow through accrual should either use wider arithmetic or be capped before conversion back to `i128`. In particular, accrual should handle `scaled * index` results above `i128::MAX` without bricking subsequent withdrawals and repayments, and withdrawal sizing should not unconditionally unscale the entire position before processing a partial request. [7](#0-6) [10](#0-9) 

Caps should also be constrained by the maximum value reachable at the configured index ceiling, or a lower protocol-wide RAY-value ceiling should be enforced before accepting additional exposure. [15](#0-14) 

### Proof of Concept
The repository already contains a real-execution regression demonstrating the issue:

1. Create an 18-decimal `BIG18` market using the steep XLM rate curve and permit cap-domain-sized positions.
2. Supply `1_000_000_000 * 10^18` base units to the market.
3. From a collateralized account, borrow `98%` of that market’s liquidity.
4. Advance ledger time through repeated accrual periods until the borrowed or supplied RAY value exceeds `i128::MAX`.
5. `update_indexes` fails with `MathOverflow` before `MAX_BORROW_INDEX_RAY` is reached.
6. A one-base-unit `withdraw` and a subsequent `repay` also fail with `MathOverflow`, leaving the market frozen. [14](#0-13)

### Citations

**File:** contracts/pool/README.md (L161-167)
```markdown
```text
entrypoint (#[only_owner])
  → Cache::load             # read params + state, bump TTL
  → interest::global_sync   # accrue to now, in ≤1yr chunks
  → mutate                  # cache/shares.rs, cache/cash.rs
  → guards::*               # reserve, utilization, backing checks
  → commit → transfer_out → emit
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

**File:** common/src/rates/scaling.rs (L14-16)
```rust
pub fn scaled_to_original(env: &Env, scaled: Ray, index: Ray) -> Ray {
    scaled.mul(env, index)
}
```

**File:** common/src/rates/scaling.rs (L105-120)
```rust
pub fn resolve_withdrawal(
    env: &Env,
    amount: i128,
    pos_scaled: Ray,
    supply_index: Ray,
    decimals: u32,
) -> (Ray, i128) {
    let current_supply_actual = unscale_supply(env, pos_scaled, supply_index, decimals);
    let current_supply_floor = unscale_supply_floor(env, pos_scaled, supply_index, decimals);
    if amount >= current_supply_actual {
        return (pos_scaled, current_supply_floor);
    }
    (
        calculate_scaled_supply_ceil(env, amount, decimals, supply_index),
        amount,
    )
```

**File:** common/src/math/fp.rs (L49-56)
```rust
    /// Multiplies two ray values, rounding the result half up.
    pub fn mul(self, env: &Env, other: Ray) -> Ray {
        Ray(fp_core::mul_div_half_up(env, self.0, other.0, RAY))
    }

    /// Divides this value by `other`, rounding the result half up.
    pub fn div(self, env: &Env, other: Ray) -> Ray {
        Ray(fp_core::mul_div_half_up(env, self.0, RAY, other.0))
```

**File:** common/src/validation.rs (L48-69)
```rust
pub fn max_cap_for_decimals(asset_decimals: u32) -> i128 {
    let Some(exp) = RAY_DECIMALS.checked_sub(asset_decimals) else {
        return 0;
    };
    let upscale = 10i128
        .checked_pow(exp)
        .expect("10^(RAY_DECIMALS - asset_decimals) fits i128 for asset_decimals <= RAY_DECIMALS");
    i128::MAX / upscale
}

/// Panics with `CollateralError::AssetDecimalsTooHigh` if `asset_decimals`
/// exceeds `RAY_DECIMALS`, or with `CollateralError::InvalidBorrowParams` if
/// `cap` exceeds the value returned by `max_cap_for_decimals`.
pub fn require_cap_within_asset_domain(env: &Env, cap: i128, asset_decimals: u32) {
    if RAY_DECIMALS.checked_sub(asset_decimals).is_none() {
        panic_with_error!(env, CollateralError::AssetDecimalsTooHigh);
    }
    assert_with_error!(
        env,
        cap <= max_cap_for_decimals(asset_decimals),
        CollateralError::InvalidBorrowParams
    );
```

**File:** docs/reference/formulas.md (L423-437)
```markdown
| Bound | Consequence |
|---|---|
| Asset decimals 0..=18 | Exact token-to-RAY upscaling. Below 3: collateral only, no flash loans, no liquidation fee, its account's only supply position, at least 2 whole units while in debt |
| Both indexes initially RAY; ceiling 10^36 | 10^9 times initial index; protocol constants |
| Supply-index floor 10^24 | At most 1,000 times the shares minted at index one for the same deposit |
| Borrow APR maximum 2 RAY | 200% annual rate; not a bound on balance growth alone |
| Token-to-RAY input maximum `i128::MAX / 10^(27-d)` | About 170.14 billion whole tokens, before other limits |
| Deposit conversion at the supply-index floor | About 170.14 million whole tokens before scaled-share overflow |

The token-to-RAY maximum is also the admitted cap maximum. Accrued position
values and market totals must independently fit the RAY domain; valid caps and
bounded indexes do not guarantee that future accrual fits. Value overflow can
occur before the index ceiling and block repayment/withdrawal because those
operations accrue first. At the borrow-index ceiling, further accrual produces
no borrower interest. No dedicated ceiling alarm is emitted.
```

**File:** contracts/pool/src/cache/scale.rs (L19-26)
```rust
    pub(crate) fn calculate_utilization(&self) -> Ray {
        if self.supplied == Ray::ZERO {
            return Ray::ZERO;
        }
        let total_borrowed = scaled_to_original(&self.env, self.borrowed, self.borrow_index);
        let total_supplied = scaled_to_original(&self.env, self.supplied, self.supply_index);

        utilization(&self.env, total_borrowed, total_supplied)
```

**File:** common/src/math/fp_core.rs (L104-118)
```rust
/// Computes `x * y / d` rounded half up. Requires `x >= 0`, `y >= 0`, and `d > 0`; a
/// `debug_assert` checks this in debug builds. Panics with `GenericError::DivisionByZero` if
/// `d == 0`, and with `GenericError::MathOverflow` if any other precondition is violated or if
/// the result does not fit in `i128`.
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

**File:** common/src/math/fp_core.rs (L138-143)
```rust
    let (x256, y256, d256) = to_i256_operands(env, x, y, d);
    x256.mul(&y256)
        .add(&I256::from_i128(env, half))
        .div(&d256)
        .to_i128()
}
```

**File:** contracts/pool/src/ops/withdraw.rs (L57-79)
```rust
pub(crate) fn accounting(
    env: &Env,
    is_liquidation: bool,
    entry: &PoolWithdrawEntry,
) -> WithdrawOutcome {
    require_nonneg_amount(env, entry.protocol_fee);
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

**File:** tests/test-harness/tests/controller/extreme_amount_inputs.rs (L85-95)
```rust
#[test]
fn supply_of_half_i128_max_is_a_typed_overflow_not_a_host_trap() {
    let mut t = setup(7);
    let alice = t.get_or_create_user(ALICE);
    let huge = i128::MAX / 2;
    t.resolve_market("A").token_admin.mint(&alice, &huge);
    let result = t
        .ctrl_client()
        .try_supply(&alice, &0, &HARNESS_SPOKE, &leg(&t, "A", huge));
    assert_contract_error(map_try_ok_value(result), errors::MATH_OVERFLOW);
}
```

**File:** contracts/controller/src/positions/supply.rs (L100-135)
```rust
pub(crate) fn process_deposit(
    env: &Env,
    caller: &Address,
    account: &mut Account,
    aggregated: &AggregatedPayments,
    cache: &mut Context,
) {
    validate_position_entry_gates(
        env,
        account,
        aggregated,
        cache,
        AccountPositionType::Deposit,
    );
    let pool_addr = cache.cached_pool_address();
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
        merge_supply_leg(env, account, &entry.action, &result, cache);
    });
```
