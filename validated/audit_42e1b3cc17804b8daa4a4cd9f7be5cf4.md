### Title
Scaled-value i128 overflow in `scaled_to_original` permanently freezes a market before the borrow-index cap can engage - (File: contracts/pool/src/cache/scale.rs)

### Summary
CVE-2017-8361 is a crafted-input buffer overflow in `flac_buffer_copy` that crashes or corrupts the process. The analog in XOXNO Lending is an arithmetic "overflow at the boundary" in the RAY share machinery: debt growth is bounded by the borrow-index cap `MAX_BORROW_INDEX_RAY`, but the check that actually overflows first is the *value* conversion `scaled * index`, which must fit in `i128`. Because every pool verb accrues interest first, once `scaled_borrowed * borrow_index` exceeds `i128::MAX` the accrual panics with `MathOverflow` and the market is permanently frozen — no repay, withdraw, liquidation, or `clean_bad_debt` can ever execute, even though the index cap that was supposed to prevent this regime never fired.

### Finding Description
`Cache::calculate_utilization` and every accrual path convert scaled RAY share counts back to asset-denominated RAY values via `scaled_to_original(env, scaled, index)`, which is `mul_div` on `i128` and panics with `GenericError::MathOverflow` when the product exceeds `i128::MAX` [1](#0-0) . The same conversion underlies `unscale_borrow`/`unscale_borrow_ceil` used by repay, liquidate, and bad-debt cleanup [2](#0-1) .

The protocol's safety bound is an index cap (`MAX_BORROW_INDEX_RAY`), but the cap compares the *index*, not the *scaled value*. For large markets the value ceiling is reached first: a billion whole tokens at 18 decimals is ~1e36 raw units, and `i128::MAX` ≈ 1.7e38 is only ~170x that, so a borrow index of ~170x already overflows — far below the index cap [3](#0-2) . The project's own harness demonstrates this: at 98% utilization on the XLM rate curve the market crosses the value ceiling, `update_indexes` fails with `MATH_OVERFLOW`, `borrow_index < MAX_BORROW_INDEX_RAY` (cap never engaged), and subsequent `withdraw` and `repay` both revert with the same overflow because every verb accrues first [4](#0-3) . The test also notes the bound documented in `docs/reference/formulas.md` is wrong [5](#0-4) .

Attack path for a single unprivileged address: `controller.supply` a very large principal into an 18-decimal market, `controller.borrow` up to ~98% of it (collateralized by a second `supply` in another market), then let time accrue (or combine with repeated `update_indexes` calls, which are permissionless). Once the product overflows, `withdraw`/`repay`/`liquidate`/`clean_bad_debt`/`flash_loan` on that (hub, token) book all revert permanently — including liquidations, so the position cannot even be unwound and lender funds are locked.

### Impact Explanation
Permanent freezing of funds: all supplier principal and accrued yield in the affected market become unrecoverable, and the underwater debt can never be liquidated or cleaned, i.e. the book becomes frozen bad debt. The panic is not a transient fail-closed rejection — no sequence of calls restores operation, because accrual is the mandatory first step of every entrypoint and the scaled totals only grow.

### Likelihood Explanation
Medium. It requires whale-scale capital (on the order of a billion 18-decimal units supplied) and sustained near-max utilization for the index to reach ~170x, which the harness shows takes on the order of years on the steep XLM curve — but it needs no privilege, no oracle manipulation, and no cooperation; any single funded account can position a market at the cliff edge, and permissionless `update_indexes` lets anyone trigger the freezing accrual once the bound is crossed. The index cap that was designed to prevent runaway growth provably does not protect this bound.

### Recommendation
Enforce the ceiling where it actually binds: in the accrual/index-update path, clamp or reject the index at a per-market bound derived from `i128::MAX / supplied_scaled` (and `borrowed_scaled`) rather than a global `MAX_BORROW_INDEX_RAY`, or make `scaled_to_original` saturate/halt accrual gracefully instead of panicking so repay/withdraw/liquidate remain executable past the bound. At minimum, fix the documented bound in `docs/reference/formulas.md` to reflect value-ceiling reachability at realistic sizes.

### Proof of Concept
```rust
// tests/test-harness/tests/controller/large_positions_and_long_horizons.rs
let mut t = LendingTest::new()
    .with_market(big("BIG18", 18, xlm_curve()))
    .with_market(col())
    .with_max_utilization_disabled_all_markets()
    .build();
lift_caps(&t, "BIG18", 18);
lift_caps(&t, "COL", 7);
let principal = BILLION * 10i128.pow(18);
t.supply_raw(BOB, "BIG18", principal);            // unprivileged supply
let debt = principal / 100 * 98;
t.supply_raw(ALICE, "COL", BILLION * 10_000_000 * 3);
t.borrow_raw(ALICE, "BIG18", debt);               // unprivileged borrow ~98% util

loop {                                            // anyone calls update_indexes
    t.advance_time(YEAR_SECS);
    if let Err(e) = t.try_update_indexes_for(&["BIG18"]) { break e; }
}
// update_indexes -> MATH_OVERFLOW; borrow_index < MAX_BORROW_INDEX_RAY
// withdraw -> MATH_OVERFLOW; repay -> MATH_OVERFLOW  (market frozen forever)
```

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
