### Title
Donation-based inflation of Aquarius LP fair-value price enables over-borrowing - (File: contracts/price-aggregator/src/providers/aquarius.rs)

### Summary
The price-aggregator derives the collateral value of Aquarius LP shares from the pool's *live* reserves read via `get_reserves`, priced as `2 * sqrt(value_a * value_b) / total_shares` for constant-product pools (`fair_lp_price_wad`) or `D * min(price_a, price_b) / total_shares` for stable pools (`fair_stable_lp_price_wad`). Both formulas grow when raw token balances in the pool grow, and neither distinguishes traded reserves from tokens directly transferred ("donated") to the pool contract. An unprivileged attacker can transfer either pool token directly to the Aquarius pool, inflating the LP share price returned to the controller, then borrow against LP collateral at the inflated valuation — the same donation/price-manipulation class as the Zunami incident.

### Finding Description
`aquarius::read` fetches `reserve_a`/`reserve_b` from the pool on every resolution and feeds them into the fair-value math [1](#0-0) . In `fair_lp_price_wad`, total value is `2 * sqrt(value_a * value_b)`, so a donation of token A of size `D` multiplies the computed LP price by `sqrt(1 + D / value_a)` with no offsetting term [2](#0-1) . The stable variant is equally affected: `solve_stable_d` scales roughly linearly with the sum of reserves, so donating either coin raises `D` and therefore `D * min_price / supply` [3](#0-2) .

The only backstops are `min_pool_value_wad` (a floor, not a ceiling) and the sanity band. LP oracles are sole-source and exempt from tolerance checks, with the band merely capped by `MAX_LP_SANITY_BAND_BPS` — and deployed bands are extremely wide (e.g., XLMAQUA_LP allows ~10× between min and max, XLMUSDC_LP ~5.5×) [4](#0-3) [5](#0-4) . A donation multiplying reserves a few times stays comfortably inside these bands. The "fair price" formulas are manipulation-resistant only against *swap* ratio shifts (the donated value is implicitly assumed balanced); a one-sided transfer breaks that assumption while still raising the computed value.

### Impact Explanation
Protocol insolvency / theft of user funds. The attacker supplies LP shares as collateral to a spoke, donates the cheaper pool token to the Aquarius pool (optionally flash-funded via `flash_loan`), and calls `borrow` while the controller's Context-cached strict price reflects the inflated LP value. LTV-weighted collateral and health factor are computed at the inflated price, so the attacker borrows more than the collateral's true value and abandons the position, leaving bad debt to be socialized via supply-index write-down.

### Likelihood Explanation
Requires an LP-token market usable as collateral and an Aquarius pool whose reserves can be moved by a direct transfer. The attacker recaptures a fraction of the donation equal to their share of the pool's liquidity, so the attack is cheapest when the attacker dominates LP supply or the pool is shallow; `min_pool_value_wad` only gates very small pools. The needed inflation (e.g., +40–100%) is far inside the configured multi-x LP sanity bands, and reserve reads are live with no smoothing or TWAP on the reserve leg. Severity: High.

### Recommendation
Value LP shares independently of instantaneous raw balances — e.g., track each leg's reserve through a manipulation-resistant accumulator, or price the LP as the sum of claimable underlying using oracle-priced worst-case redemption rather than `sqrt(value_a * value_b)` on live balances. At minimum, bound the reserve ratio or compare the live reserve-derived price against a stored/TWAP'd pool virtual price, and tighten `MAX_LP_SANITY_BAND_BPS` so deployed bands bracket only plausible fee accrual drift.

### Proof of Concept
1. Attacker acquires a large position in Aquarius pool P (tokens A/B) and supplies the LP shares as collateral via `controller.supply` on a spoke listing the LP token.
2. Via `flash_loan` (or own funds), attacker transfers amount `D` of token A directly to pool P's address, raising `reserve_a` while `total_shares` is unchanged.
3. `aquarius::read` now returns `price' = 2*sqrt((va + D·pa)·vb)/supply ≈ price * sqrt(1 + D/va)`; with `D ≈ 3·va`, price ~2× — inside the LP sanity band.
4. Attacker calls `borrow` for ~2× the true collateral value, withdraws, and lets the position go bad; `clean_bad_debt`/recapitalize absorbs the shortfall from suppliers.

### Citations

**File:** contracts/price-aggregator/src/providers/aquarius.rs (L90-114)
```rust
    let (reserve_a, reserve_b) =
        aquarius_pool_reserves_call(&env, &lp.pool).ok_or(OracleError::NoLastPrice)?;
    let total_shares =
        aquarius_total_shares_call(&env, &lp.pool).ok_or(OracleError::NoLastPrice)?;

    let leg_a = LpLeg {
        reserve: reserve_a,
        decimals: lp.reserve_a_decimals,
        price_wad: price_a.price_wad,
    };
    let leg_b = LpLeg {
        reserve: reserve_b,
        decimals: lp.reserve_b_decimals,
        price_wad: price_b.price_wad,
    };
    let supply = LpSupply {
        total_shares,
        decimals: share_decimals,
    };
    let price_wad = if stable {
        let amp = aquarius_amp_call(&env, &lp.pool).ok_or(OracleError::NoLastPrice)?;
        fair_stable_lp_price_wad(&env, &leg_a, &leg_b, &supply, amp)?
    } else {
        fair_lp_price_wad(&env, &leg_a, &leg_b, &supply)?
    };
```

**File:** common/src/oracle/lp.rs (L72-86)
```rust
    let value_a = reserve_value_wad(env, a)?;
    let value_b = reserve_value_wad(env, b)?;

    let total_value =
        isqrt_of_product(env, value_a as u128, value_b as u128).mul(&U256::from_u32(env, 2));

    let share_supply_wad = try_amount_to_wad(env, supply.total_shares, supply.decimals)?;
    if share_supply_wad <= 0 {
        return Err(OracleError::InvalidPrice);
    }
    let fair = total_value
        .mul(&U256::from_u128(env, WAD as u128))
        .div(&U256::from_u128(env, share_supply_wad as u128));

    try_u256_to_i128(&fair).ok_or(OracleError::InvalidPrice)
```

**File:** common/src/oracle/lp_stable.rs (L96-109)
```rust
    let xa_wad = try_amount_to_wad(env, a.reserve, a.decimals)?;
    let xb_wad = try_amount_to_wad(env, b.reserve, b.decimals)?;
    let d = solve_stable_d(env, xa_wad, xb_wad, amp)?;

    let min_price = a.price_wad.min(b.price_wad);
    let share_supply_wad = try_amount_to_wad(env, supply.total_shares, supply.decimals)?;
    if share_supply_wad <= 0 {
        return Err(OracleError::InvalidPrice);
    }

    let fair = d
        .mul(&U256::from_u128(env, min_price as u128))
        .div(&U256::from_u128(env, share_supply_wad as u128));
    try_u256_to_i128(&fair).ok_or(OracleError::InvalidPrice)
```

**File:** common/src/validation.rs (L198-208)
```rust
/// Asserts that the sanity band width between `min_wad` and `max_wad`, in basis
/// points and rounded up, does not exceed `MAX_LP_SANITY_BAND_BPS`, panicking with
/// `OracleError::SanityBandTooWideForSingleSource` otherwise.
pub fn validate_lp_sanity_band(env: &Env, min_wad: i128, max_wad: i128) {
    let band_bps = mul_div_ceil(env, max_wad - min_wad, BPS, max_wad + min_wad);
    assert_with_error!(
        env,
        band_bps <= MAX_LP_SANITY_BAND_BPS,
        OracleError::SanityBandTooWideForSingleSource
    );
}
```

**File:** common/tests/validation.rs (L549-578)
```rust
    let bands: [(i128, i128); 11] = [
        // mainnet XLMUSDC_LP
        (450_000_000_000_000_000, 2_500_000_000_000_000_000),
        // mainnet XLMSolvBTC_LP
        (25_000_000_000_000_000_000, 250_000_000_000_000_000_000),
        // mainnet xSolvBTCSolvBTC_LP
        (
            4_000_000_000_000_000_000_000,
            12_000_000_000_000_000_000_000,
        ),
        // mainnet CETESUSDC_LP
        (430_000_000_000_000_000, 610_000_000_000_000_000),
        // mainnet USTRYUSDC_LP
        (1_740_000_000_000_000_000, 2_440_000_000_000_000_000),
        // mainnet USDYUSDC_LP
        (1_790_000_000_000_000_000, 2_510_000_000_000_000_000),
        // mainnet XAUMUSDC_LP
        (6_000_000_000_000_000_000, 25_000_000_000_000_000_000),
        // mainnet PYUSDUSDC_LP
        (900_000_000_000_000_000, 1_200_000_000_000_000_000),
        // mainnet XLMAQUA_LP
        (5_356_670_329_052_813, 53_566_703_290_528_136),
        // mainnet AQUAUSDC_LP
        (12_851_039_215_266_326, 128_510_392_152_663_280),
        // testnet XLMUSDC_LP
        (400_000_000_000_000_000, 3_000_000_000_000_000_000),
    ];
    for (min_wad, max_wad) in bands {
        validate_lp_sanity_band(&env, min_wad, max_wad);
    }
```
