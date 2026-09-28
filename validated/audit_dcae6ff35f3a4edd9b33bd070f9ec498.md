### Title
Permanent market freeze from RAY share/index overflow - (File: common/src/rates/index.rs)

### Summary

A market whose scaled supply or debt value later exceeds the `i128` RAY domain can enter an unrecoverable state: accrual panics before updating the market timestamp, and every subsequent operation on that market repeats the same panic. `common::rates::scaled_to_original` delegates to `Ray::mul`, while `calculate_supplier_rewards` multiplies total debt shares by both old and new borrow indexes; any result above `i128::MAX` raises `MathOverflow`. [1](#0-0) [2](#0-1) [3](#0-2) 

### Finding Description

Controller `supply` and `borrow` are the reachable entrypoints that can create the oversized books, subject to the configured market caps and collateral requirements. [4](#0-3) 

Pool accrual iterates over elapsed chunks and calls `accrue_step` before mutating market state. [5](#0-4) [6](#0-5) 

During accrual, utilization unscales both `borrowed * borrow_index` and `supplied * supply_index`; supply-index distribution separately calculates `supplied * old_index`, and debt interest calculates `borrowed * new_borrow_index`. [7](#0-6) [8](#0-7) [3](#0-2) 

The underlying fixed-point routine returns `None` when the exact quotient does not fit `i128`, and the public `mul_div_half_up` wrapper converts that into `MathOverflow`. [9](#0-8) [10](#0-9) 

Because the panic occurs inside accrual before `mark_accrued`, `last_timestamp` remains stale and every later transaction attempts the same overflowing calculation. [5](#0-4) [11](#0-10) 

The admitted token cap only bounds the initial token-to-RAY conversion and does not reserve room for index growth, so a book admitted at index `1 RAY` can become unrepresentable before either index reaches its protocol ceiling. [12](#0-11) 

### Impact Explanation

Once the boundary is crossed, the affected market cannot process repayment or withdrawal because both pool paths synchronize and unscale positions before changing balances. [13](#0-12) [14](#0-13) 

This permanently freezes supplier principal and yield in that market, prevents borrowers from repaying or closing the debt, and prevents liquidations or cleanup from unwinding the impaired book through the pool’s normal synchronized operations. [15](#0-14) [16](#0-15) 

The repository’s regression test demonstrates the terminal state explicitly: `update_indexes`, `withdraw`, and `repay` all fail with `MathOverflow`, while the stored borrow index remains below its protocol cap. [17](#0-16) 

### Likelihood Explanation

A single unprivileged address can create the state by supplying a very large amount of a listed high-decimal asset, borrowing enough of it under the configured utilization and collateral limits, and letting the market indexes grow. [4](#0-3) [18](#0-17) 

The condition does not require privileged calls, malformed XDR, token semantics, or oracle manipulation; it requires a market whose configured caps admit scaled totals large enough that normal interest accrual eventually makes `scaled * index / RAY` exceed `i128::MAX`. [12](#0-11) 

`Controller::update_indexes` is permissionless, so any caller can trigger the terminal accrual once ledger time has advanced far enough; alternatively, the next user repayment, withdrawal, liquidation, or other synchronized pool operation triggers it. [19](#0-18) [5](#0-4) 

### Recommendation

Enforce a market-wide invariant that scaled supply and debt totals remain representable at the maximum index:

```rust
scaled <= floor(i128::MAX * RAY / MAX_*_INDEX_RAY)
```

Apply this bound when admitting supply and borrow caps, when processing supply/borrow legs, and when accrual mints revenue shares into `supplied`; do not rely on the input token-domain cap alone. [20](#0-19) [12](#0-11) 

Prefer rejecting entries that would violate the bound before shares are minted, rather than clamping or saturating debt or supply values after accrual, because saturation would misstate accounting and socialize an arbitrary loss. [21](#0-20) 

### Proof of Concept

The existing test constructs an admitted 18-decimal market with `1_000_000_000 * 10^18` supplied units and `98%` debt, advances ledger time until accrual fails, and then demonstrates that both withdrawal and repayment continue to fail. [22](#0-21) 

An on-chain reproduction is:

```text
1. attacker calls supply(
       caller=attacker,
       account_id=0,
       spoke_id=S,
       assets=[(Hcol, C)]
   ) -> collateral_account

2. attacker calls supply(
       caller=attacker,
       account_id=0,
       spoke_id=S,
       assets=[(Hbig, P)]
   ) -> liquidity_account
   where P is large enough that P * future_index / RAY exceeds i128::MAX.

3. attacker calls borrow(
       caller=attacker,
       account_id=collateral_account,
       borrows=[(Hbig, B)],
       to=attacker
   )
   where B is positive and within configured collateral, borrow-cap, and
   utilization limits; larger B accelerates index growth.

4. Any caller invokes update_indexes(caller, [Hbig]) after enough accrual.
   The call panics before committing a new timestamp.

5. withdraw, repay, liquidate, clean_bad_debt, and recapitalize touching Hbig
   subsequently repeat accrual and fail with MathOverflow.
```

The test verifies that the resulting borrow index remains below `MAX_BORROW_INDEX_RAY`, proving that the index cap is not the protection that prevents this freeze. [23](#0-22)

### Citations

**File:** common/src/rates/scaling.rs (L12-16)
```rust
/// Converts a scaled `Ray` amount to its original (unscaled) value by
/// multiplying by `index`, rounding half up.
pub fn scaled_to_original(env: &Env, scaled: Ray, index: Ray) -> Ray {
    scaled.mul(env, index)
}
```

**File:** common/src/rates/scaling.rs (L20-32)
```rust
/// The division saturates at `i128::MAX` instead of panicking, so the cap check
/// fails open rather than trapping an entry path. The asset-to-RAY
/// rescale still panics on overflow; listings validate caps with
/// [`crate::validation::require_cap_within_asset_domain`]. Position accounting
/// uses [`calculate_scaled_supply`] and [`calculate_scaled_borrow`], which panic
/// on overflow.
pub fn calculate_scaled_cap(env: &Env, cap: i128, decimals: u32, index: Ray) -> Ray {
    Ray::from(fp_core::mul_div_floor_saturating(
        env,
        Ray::from_asset(env, cap, decimals).raw(),
        RAY,
        index.raw(),
    ))
```

**File:** common/src/math/fp.rs (L49-52)
```rust
    /// Multiplies two ray values, rounding the result half up.
    pub fn mul(self, env: &Env, other: Ray) -> Ray {
        Ray(fp_core::mul_div_half_up(env, self.0, other.0, RAY))
    }
```

**File:** common/src/rates/index.rs (L29-35)
```rust
pub fn update_supply_index(env: &Env, supplied: Ray, old_index: Ray, rewards_increase: Ray) -> Ray {
    if supplied == Ray::ZERO || rewards_increase == Ray::ZERO {
        return old_index;
    }

    let total_supplied_value = supplied.mul(env, old_index);

```

**File:** common/src/rates/index.rs (L80-83)
```rust
    let old_total_debt = borrowed.mul(env, old_borrow_index);
    let new_total_debt = borrowed.mul(env, new_borrow_index);

    let accrued_interest = new_total_debt.checked_sub(env, old_total_debt);
```

**File:** common/src/rates/index.rs (L94-98)
```rust
pub fn protocol_fee_shares(env: &Env, fee: Ray, supply_index: Ray, supplied: Ray) -> Ray {
    let raw = fp_core::mul_div_floor_saturating(env, fee.raw(), RAY, supply_index.raw());

    let headroom = i128::MAX.saturating_sub(supplied.raw());
    Ray::from(raw.min(headroom))
```

**File:** contracts/controller/src/lib.rs (L94-114)
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
```

**File:** contracts/controller/src/lib.rs (L120-157)
```rust
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
    }

    /// Repays debt and seizes collateral at a health-factor-based bonus.
    /// Permissionless, including self-liquidation; requires liquidator authorization.
    /// Residual bad debt is socialized only at or below the collateral dust cap.
    ///
    /// `Transfer` pays pool cash and returns `0`. `Credit(id)` moves net supply
    /// shares to a different, authorized Normal-mode account on the same spoke;
    /// `Credit(0)` creates one. Credit mode needs no free collateral liquidity
    /// and returns the receiving account id.
    fn liquidate(
        env: Env,
        liquidator: Address,
        account_id: u64,
        debt_payments: Vec<(HubAssetKey, i128)>,
        seize_mode: SeizeMode,
    ) -> u64 {
        positions::liquidation::process_liquidation(
            &env,
            &liquidator,
            account_id,
            &debt_payments,
            seize_mode,
        )
```

**File:** contracts/pool/src/interest.rs (L25-32)
```rust
    let mut remaining = cache.elapsed_ms();
    while let Some(nonzero) = NonZeroU64::new(remaining) {
        let chunk = nonzero.get().min(MAX_COMPOUND_DELTA_MS);
        accrue_chunk(env, cache, chunk);
        remaining = remaining.saturating_sub(chunk);
    }

    cache.mark_accrued();
```

**File:** contracts/pool/src/interest.rs (L40-48)
```rust
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

**File:** common/src/math/fp_core.rs (L116-118)
```rust
    try_mul_div_half_up(env, x, y, d)
        .unwrap_or_else(|| panic_with_error!(env, GenericError::MathOverflow))
}
```

**File:** common/src/math/fp_core.rs (L120-124)
```rust
/// Computes `x * y / d` rounded half up. Returns `None` if `x < 0`, `y < 0`, `d <= 0`, or the
/// result does not fit in `i128`.
pub fn try_mul_div_half_up(env: &Env, x: i128, y: i128, d: i128) -> Option<i128> {
    if x < 0 || y < 0 || d <= 0 {
        return None;
```

**File:** contracts/pool/src/cache/mod.rs (L143-146)
```rust
    /// Marks the market as fully accrued through `current_timestamp`.
    pub(crate) fn mark_accrued(&mut self) {
        self.last_timestamp = self.current_timestamp;
    }
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

**File:** contracts/pool/src/ops/repay.rs (L22-24)
```rust
/// Accrues interest, burns the position's debt shares, credits the net repay to cash,
/// commits the market state, and transfers any overpayment back to the payer.
/// The returned mutation's `actual_amount` is the net repay, excluding overpayment.
```

**File:** contracts/pool/src/ops/withdraw.rs (L25-29)
```rust
/// Accrues interest, burns supply shares, debits cash, and transfers the net
/// proceeds to `receiver`.
///
/// Mutation `actual_amount` is the **gross** withdrawal; `net_transfer` is what
/// leaves the pool after any liquidation fee.
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

**File:** docs/reference/endpoints.md (L37-40)
```markdown
| `update_indexes(caller: Address, assets: Vec<HubAssetKey>)` | None | gated | Accrue specified markets. |
| `claim_revenue(caller: Address, assets: Vec<HubAssetKey>) -> Vec<i128>` | None | gated | Pay only configured accumulator; return controller receipts. |
| `update_account_threshold(caller: Address, has_risks: bool, account_ids: Vec<u64>)` | None | gated | Refresh LTV; optional risk refresh requires final HF >= 1.05. |
| `recapitalize(payer: Address, hub_asset: HubAssetKey, amount: i128) -> i128` | None | open | Measured backing injection; refund surplus; return amount applied. |
```
