### Title
Aquarius LP oracle derives the "amount" side of LP valuation from live, manipulable pool reserves - ([File: contracts/price-aggregator/src/providers/aquarius.rs](contracts/price-aggregator/src/providers/aquarius.rs))

### Summary
The Aquarius LP price provider splits LP valuation into a protected component (the two leg token prices, resolved through the full dual-leg tolerance / staleness / sanity pipeline via `engine::resolve_nested`) and an unprotected component (the pool's `reserve_a`/`reserve_b` and `total_shares`, read live from the pool contract). This mirrors the Revert `V3Oracle::getValue()` bug class: the *price* inputs are manipulation-resistant, but the *quantity* inputs (`reserve_a`, `reserve_b`, `total_shares`) come from spot pool state that an unprivileged attacker can distort inside the same transaction — by executing their own swaps against the Aquarius pool or by transferring tokens directly to the pool address — before calling a valuation-dependent controller entrypoint such as `borrow`, `withdraw`, `multiply`, `flash_position`, or `liquidate` on an account holding LP-share collateral. The resulting LP-share `price_wad` is then consumed as the collateral `feed.price` in `calculate_account_risk_totals` / `calculate_seized_collateral`, so the distortion propagates directly into health factor and seizure sizing.

### Finding Description
In `aquarius::read` (`contracts/price-aggregator/src/providers/aquarius.rs:88-114`):

- `price_a`/`price_b` are resolved through `engine::resolve_nested`, which enforces staleness, dual-source tolerance bands, and sanity bounds — these are the "validated" inputs, equivalent to Revert's `price0X96/price1X96`.
- `reserve_a`, `reserve_b`, and `total_shares` are read from the pool's own `get_reserves`/`total_shares` entrypoints at `aquarius.rs:90-93` — instantaneous, single-ledger state, equivalent to Revert's `slot0()`-derived `amount0/amount1`.
- Constant-product pools compute `fair_lp_price_wad = 2 * sqrt(reserve_a*price_a * reserve_b*price_b) * WAD / supply_wad` (`common/src/oracle/lp.rs:57-87`); stable pools compute `fair_stable_lp_price_wad = D(reserves) * min(price_a, price_b) / supply_wad` (`common/src/oracle/lp_stable.rs:80-110`).

Both formulas are designed to be *swap-neutral* (a swap moves reserves along the invariant, leaving `sqrt(va·vb)` or `D` roughly constant), but neither is *reserve-donation-neutral*: a direct token transfer to the pool, or an imbalanced liquidity deposit, raises `reserve_a`/`reserve_b` without proportionally raising `total_shares`, inflating the computed per-share fair value. The only guards are `min_pool_value_wad` (`aquarius.rs:118-121`), which checks total pool value rather than manipulation, and the leg-price sanity bands, which constrain token prices but not reserve composition. Unlike the fixed-mitigation in Revert (compute amounts at oracle price), there is no cross-check that the reserve ratio is consistent with the oracle-implied price ratio `price_a/price_b` — a constant-product pool whose reserve ratio diverges from the oracle ratio is by definition holding excess donated/skewed units, yet the fair-value formula still credits the geometric mean of both reserve values.

The consumed value lands in `cache.cached_price(...)` used by `position_value_floor`/`position_value_ceil` in `contracts/controller/src/risk/totals.rs:171-201` (borrow/withdraw solvency gate) and by `calculate_seized_collateral` in `contracts/controller/src/positions/liquidation/math.rs:383-399` (seizure split and per-leg amount, which divides USD by `feed.price`).

### Impact Explanation
An attacker holding LP-share collateral can inflate the LP `price_wad` used for their account's `ltv_collateral`/`weighted_collateral`/`total_collateral`, then `borrow` (or `multiply`/`flash_position`) more than the true collateral value supports, leaving bad debt that is later socialized via `clean_bad_debt` / supply-index write-down — protocol insolvency borne by suppliers. Conversely, deflating reserves skews liquidation inputs for other accounts. Because the attacker's own donation raises every LP share's fair price, an attacker controlling a large share fraction of a thin pool can turn a bounded donation into outsized borrowing power; the profit bound is only economic (donation cost vs. LTV × share-fraction × inflation), not a hard invariant, and `min_pool_value_wad` does not detect the per-share distortion.

### Likelihood Explanation
Requires a listed collateral market priced through an `AquariusLp` source (`AquariusLpSource` in `common/src/types/composable_oracle.rs:125-130`), plus enough capital to move the pool's reserve composition. All paths are unprivileged: direct token transfers to the pool, own swaps on Aquarius, and `controller.borrow`/`multiply`. The sqrt damping on constant-product pools and the `D`-invariant on stable pools bound the inflation per unit of spent capital, and `min_pool_value_wad` plus leg sanity bands exclude degenerate cases, so exploitation is confined to thin or attacker-dominated pools — consistent with Medium severity, matching the judge's downgrade of the original report.

### Recommendation
Bind the quantity inputs to the validated price inputs, as in the Revert fix:

1. Reject the read (or clamp to the oracle-implied reserves) when the implied pool price ratio `reserve_b * 10^dec_a / (reserve_a * 10^dec_b)` deviates from `price_a / price_b` beyond a configured tolerance in `aquarius::read` — a direct analog of "compute amounts at the oracle price".
2. For stable pools, additionally bound `D / total_shares` against a configured per-share ceiling relative to `min(price_a, price_b)`.
3. Treat `total_shares`/reserves freshness explicitly: document that reserve donation is a value-transfer to all LPs, and consider using the *lower* of the two reserve-value legs (`2 * min(va, vb)` instead of `2 * sqrt(va * vb)`) so one-sided reserve inflation is not credited.

### Proof of Concept
1. Governance lists LP share token `S` of a constant-product Aquarius pool (reserves `A`/`B`, priced via `key_a`/`key_b` Reflector feeds) as collateral with LTV `L`.
2. Attacker acquires a fraction `f` of `total_shares`, supplies `f * total_shares` of `S` to an account via `supply`.
3. In one transaction: attacker transfers `x` units of token `A` directly to the pool address (raising `reserve_a` to `reserve_a + x`, `total_shares` unchanged). `fair_lp_price_wad` rises by factor `sqrt(1 + x/reserve_a)`.
4. Attacker calls `borrow(account_id, [(debt_hub_asset, amount)])`. `calculate_account_risk_totals` reads the cached inflated LP `price_wad` (`totals.rs:172-198`); the post-action gate `ltv_collateral >= total_debt` passes at a borrow size that true collateral value would reject.
5. Attacker keeps the borrowed funds; the over-leveraged account is eventually liquidated/cleaned at a loss to suppliers. The oracle legs `price_a`, `price_b` were never manipulated — only the reserve inputs, exactly as in M-19 where `amount0`/`amount1` were the manipulated term. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** contracts/price-aggregator/src/providers/aquarius.rs (L88-114)
```rust
    let price_a = engine::resolve_nested(session, &lp.key_a, depth + 1)?;
    let price_b = engine::resolve_nested(session, &lp.key_b, depth + 1)?;
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

**File:** common/src/oracle/lp.rs (L57-87)
```rust
pub fn fair_lp_price_wad(
    env: &Env,
    a: &LpLeg,
    b: &LpLeg,
    supply: &LpSupply,
) -> Result<i128, OracleError> {
    if a.reserve <= 0
        || b.reserve <= 0
        || a.price_wad <= 0
        || b.price_wad <= 0
        || supply.total_shares <= 0
    {
        return Err(OracleError::InvalidPrice);
    }

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
}
```

**File:** common/src/oracle/lp_stable.rs (L80-110)
```rust
pub fn fair_stable_lp_price_wad(
    env: &Env,
    a: &LpLeg,
    b: &LpLeg,
    supply: &LpSupply,
    amp: u128,
) -> Result<i128, OracleError> {
    if a.reserve <= 0
        || b.reserve <= 0
        || a.price_wad <= 0
        || b.price_wad <= 0
        || supply.total_shares <= 0
    {
        return Err(OracleError::InvalidPrice);
    }

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
}
```

**File:** contracts/controller/src/risk/totals.rs (L171-199)
```rust
    for (hub_asset, position) in iter_typed_positions(supply_positions) {
        let feed = cache.cached_price(&hub_asset.asset);
        let market_index = cache.cached_market_index(&hub_asset);

        let value = position_value(
            env,
            position.scaled_amount,
            market_index.supply_index,
            feed.price,
        );
        let gate_value = position_value_floor(
            env,
            position.scaled_amount,
            market_index.supply_index,
            feed.price,
        );

        total_collateral = total_collateral.checked_add(env, value);
        // A gated threshold can stay below refreshed LTV; clamp the borrow limit to it.
        let effective_ltv = position.loan_to_value.min(position.liquidation_threshold);
        ltv_collateral =
            ltv_collateral.checked_add(env, effective_ltv.apply_to_wad_floor(env, gate_value));
        weighted_collateral = weighted_collateral.checked_add(
            env,
            position
                .liquidation_threshold
                .apply_to_wad_floor(env, gate_value),
        );
    }
```

**File:** contracts/controller/src/positions/liquidation/math.rs (L383-399)
```rust
    for (hub_asset, position) in iter_typed_positions(&account.supply_positions) {
        let feed = cache.cached_price(&hub_asset.asset);
        let market_index = cache.cached_market_index(&hub_asset);

        let actual_ray = position.scaled_amount.mul(env, market_index.supply_index);
        let asset_value = risk::position_value(
            env,
            position.scaled_amount,
            market_index.supply_index,
            feed.price,
        );

        let share = asset_value.div(env, total_collateral);
        let seizure_for_asset_usd = total_seizure_usd.mul(env, share);

        let seizure_amount_wad = seizure_for_asset_usd.div(env, feed.price);
        let mut seizure_ray = seizure_amount_wad.to_ray(env);
```
