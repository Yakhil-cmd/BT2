### Title
Aquarius LP collateral price is inflated by direct reserve donations, allowing over-borrowing against LP shares - (File: common/src/oracle/lp.rs)

### Summary
The Sturdy Finance bug class — manipulating the oracle-reported value of LP-token collateral — maps onto XOXNO Lending's `AquariusLp` source. The aggregator computes the fair value of an Aquarius constant-product LP share as `2 * sqrt(value_a * value_b) / total_shares` from raw pool reserves. Any unprivileged address can raise `value_a` or `value_b` by directly transferring one of the pool tokens to the pool address (no swap, no LP receipt required). The reported LP price then rises by roughly `sqrt(1 + donated_value / leg_value)`, letting a dominant LP holder over-value LP collateral supplied to `supply`, borrow against it, and recover the donation through normal LP redemption.

### Finding Description
`aquarius::read` fetches raw `reserve_a`, `reserve_b`, and `total_shares` from the pool contract, then calls `fair_lp_price_wad`, which computes the share price as `2 * sqrt(reserve_value_a * reserve_value_b) / share_supply_wad`.

- Reserve reads: `aquarius_pool_reserves_call` returns live pool balances with no reconciliation to the pool's internal accounting — a permissionless token transfer to the pool address inflates the reported reserve [1](#0-0) 
- Fair-value formula: `total_value = 2 * sqrt(value_a * value_b)`, divided by share supply [2](#0-1) 
- The only floor is `min_pool_value_wad`, which checks pool *value* and is *increased*, not defeated, by donations [3](#0-2) 
- Donation raises the reported price by `sqrt(1 + x/v)` where `x` is donated leg value: donating `x = 3v` doubles the reported price; `x = 8v` triples it.

Because the attacker already holds (or mints then holds) LP shares, the donation is not lost: it accrues pro-rata to all shares, and the attacker recovers fraction `f` of it on redemption. When the attacker owns a large share fraction `f`, the effective cost of the manipulation is `(1 - f) * x`, while the gain is the excess borrow over true collateral value.

### Impact Explanation
Theft of lender funds / protocol insolvency. The attacker supplies Aquarius LP shares as collateral via `supply`, lets `update_account_threshold`/`borrow` value them at the inflated price, borrows up to `LTV * inflated_value`, then redeems the LP to recover the donation and walks away from the position. If the inflated price exceeds true value by factor `m`, debt `D ≈ LTV * m * V_true` exceeds recoverable collateral `V_true` whenever `m > 1/LTV`, leaving bad debt that falls on suppliers via `clean_bad_debt` write-down.

### Likelihood Explanation
Requires a borrowable market against an Aquarius LP collateral listing where the attacker can acquire a dominant share fraction `f` (thin external liquidity helps) and enough capital to donate several multiples of the pool leg value. The sanity band caps the manipulation at `u = max/min` per the threat model's own bound (`LT < 1/u` is required for safety) [4](#0-3) , so exploitability depends on band width vs. LTV — the documented safety margin applies to feed drift, not to reserve donations which are an unmodeled price input. Reserve donation is permissionless and atomic within a single transaction, so no liveness or trust assumption blocks it. Medium severity: real theft vector, but bounded by the sanity band and by the attacker's need to dominate the LP supply.

### Recommendation
Anchor the LP price to a manipulation-resistant reserve reference: use the pool's reported total value or TWAP'd reserves rather than spot balances, or require both reserve legs to move only via the pool's swap path (verify balances equal the pool's internally tracked reserves if Aquarius exposes them, and reject raw balance reads that exceed tracked reserves). At minimum, tighten `MAX_LP_SANITY_BAND_BPS` so that `u <= 1/LT` for every market accepting Aquarius LP collateral, and treat the donation-inflation bound `sqrt(1 + x/v)` as part of the band budget.

### Proof of Concept
1. Attacker identifies an Aquarius constant-product pool whose LP token is listed as collateral on a spoke; external liquidity is small, so the attacker deposits both tokens and acquires ~90% of `total_shares`.
2. Attacker calls `supply` on the controller, depositing all LP shares as collateral.
3. Attacker transfers `x ≈ 3 * reserve_a_value` of token A directly to the pool address. `aquarius_pool_reserves_call` now reports the inflated reserve; `fair_lp_price_wad` reports `price ≈ 2 * sqrt(4 * v_a * v_b) / supply = 2x` the true per-share value.
4. Attacker calls `borrow` for the maximum allowed by the inflated collateral — roughly `LTV * 2 * V` vs. true collateral `V` — extracting up to ~`(2*LTV - 1) * V` of lender funds beyond true value.
5. Attacker redeems the LP shares (or sells via `swap_collateral`), recovering ~`f = 90%` of the donation; the position is left undercollateralized and eventually cleaned via `clean_bad_debt`, writing down the supply index against suppliers.

### Citations

**File:** contracts/price-aggregator/src/providers/aquarius.rs (L90-93)
```rust
    let (reserve_a, reserve_b) =
        aquarius_pool_reserves_call(&env, &lp.pool).ok_or(OracleError::NoLastPrice)?;
    let total_shares =
        aquarius_total_shares_call(&env, &lp.pool).ok_or(OracleError::NoLastPrice)?;
```

**File:** contracts/price-aggregator/src/providers/aquarius.rs (L118-121)
```rust
    let pool_value_wad = try_mul_div_half_up(&env, price_wad, total_shares, share_unit)
        .ok_or(OracleError::InvalidPrice)?;
    if pool_value_wad < lp.min_pool_value_wad {
        return Err(OracleError::InsufficientAquariusLiquidity);
```

**File:** common/src/oracle/lp.rs (L75-86)
```rust
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

**File:** docs/explanation/threat-model.md (L199-210)
```markdown
Lender safety depends only on the reported collateral prices. Bad debt occurs
only when the reported collateral is less than the debt. Take one collateral
leg with `n` units and a debt `D`. A borrow at the reported price `p1` gives
`D <= LTV * n * p1`. Bad debt at a later reported price `p2` needs
`n * p2 < D`. Both conditions need `p1 / p2 > 1 / LTV >= 1 / LT`. When
`LT < 1 / u`, `1 / LT > u`, and the band does not allow this ratio. An account
that is healthy at a report `p1` has `D <= LT * n * p1`, so the same result
applies from that report. A liquidation does not decrease the units held for
each unit of debt, so the result also applies after a liquidation. Thus
lenders cannot lose while `LT < 1 / u`. The band ratio `u` is the threshold,
not the price deviation. The Liqvid hub has LT 60% or 53% and `u` at most
11/9, so it has a large margin.
```
