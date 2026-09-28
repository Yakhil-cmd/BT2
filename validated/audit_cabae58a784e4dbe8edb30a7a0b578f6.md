### Title
Same-transaction manipulation of Aquarius LP oracle price via reserve donation enables over-borrowing - ([File: contracts/price-aggregator/src/providers/aquarius.rs])

### Summary
The reported class — an unprivileged party profiting by acting around an oracle price change — maps onto XOXNO Lending not as sandwiching an update transaction (there is no unprivileged price-update entrypoint; `set_oracle` is owner-only and `prices`/`quotes` are live read-only resolution) but as **same-transaction oracle price movement**: the Aquarius LP price source resolves `prices` from the AMM pool's *live* reserves and total shares inside the borrower's own transaction, and a direct token donation (or own trades) to that pool inflates the reported LP share price.

### Finding Description
`aquarius::read` computes the LP share price from `aquarius_pool_reserves_call` and `aquarius_total_shares_call` read at call time, with no smoothing, TWAP, or historical checkpoint on the reserve values ( [1](#0-0) ). `fair_lp_price_wad` prices one share as `2 * sqrt(value_a * value_b) / share_supply_wad` where `value_x = reserve * price_wad / 10^decimals` ( [2](#0-1) ). A donation of token A to the Aquarius pool raises `reserve_a`, raising the LP price by `sqrt(1 + D/Va)`.

Admission validation (`aquarius_lp_shape`) only requires positive `min_pool_value_wad`, distinct tokens/keys, and valid decimals — nothing prevents a market's collateral oracle from resolving through reserves an attacker can move atomically ( [3](#0-2) ). The controller's risk path then consumes this price unconditionally: `calculate_ltv_collateral_wad` multiplies the position value by `feed.price` fetched from the aggregator in the same invocation ( [4](#0-3) ; [5](#0-4) ). Soroban transactions are atomic, so the donation, the price read, the `borrow`, and the liquidity withdrawal all execute in one transaction.

Because the attacker can hold the pool's LP shares (and the fair-value formula only needs `2*sqrt`, i.e., dampened inflation), the donation is largely recoverable via pro-rata liquidity withdrawal after borrowing — cost is bounded to AMM fees plus the fraction of reserves owned by other LPs, while the gain is debt drawn against inflated collateral.

### Impact Explanation
Theft of protocol funds / insolvency: an attacker inflates the reported value of LP-token collateral within the sanity band, borrows more than true LTV allows via `borrow` (or inflates `multiply`/`flash_position` leverage), and leaves under-collateralized debt that becomes bad debt borne by suppliers. Magnitude is capped by the configured `[min_sanity_price_wad, max_sanity_price_wad]` band and by the square-root dampening (quadrupling a leg's value only doubles the price), so this is bounded manipulation, not arbitrary.

### Likelihood Explanation
Requires: (a) a collateral market whose oracle resolves through an `AquariusLp`/`AquariusStableLp` source, (b) enough capital to dominate the referenced Aquarius pool's liquidity (to recover the donation) and to fund the quadratic donation, and (c) the resulting inflated price staying inside the sanity band and, for dual-source configs, inside the cross-source tolerance band — which effectively limits the clean exploit to single-source LP configurations or to manipulating both disjoint pools at once. One caveat: `validation::smoothing` rejects configurations whose first source has an unsmoothed market leg with no smoothed second source (`SpotOnlyNotProductionSafe`, validation.rs:56-65); whether an `AquariusLp` source is classified as an unsmoothed market leg (`SourceProperties::has_unsmoothed_market_leg`) was not fully confirmed and determines whether a single-source LP oracle is admissible at all. Medium is appropriate given these gating conditions.

### Recommendation
- Read Aquarius reserves through a manipulation-resistant lens: snapshot/TWAP reserves, or require `min_pool_value_wad` high enough that the donation needed to reach the sanity-band ceiling exceeds plausible extractable profit.
- Require two disjoint sources (with `RequireDisjoint`) for any oracle that resolves through on-chain DEX reserves, so a single atomic manipulation trips the tolerance gate (`UnsafePriceNotAllowed`).
- Consider a per-transaction/per-ledger price change cap or minimum observation age for LP-derived prices.

### Proof of Concept
1. Attacker deposits balanced liquidity into Aquarius pool P (XLM/USDC), receiving most of the LP shares; governance has listed the LP token as collateral whose oracle is `PriceSource::AquariusLp { pool: P, key_a: XLM, key_b: USDC, ... }`.
2. Attacker supplies the LP tokens to the controller via `supply`, enabling them as collateral.
3. In one transaction: transfer a large amount of XLM directly to P (raising `reserve_a`), call controller `borrow(USDC, amount)` — `Context::fetch_prices` → `prices` → `aquarius::read` sees the inflated reserves and reports a `sqrt`-scaled higher LP price → solvency gate passes on inflated collateral → receive borrowed USDC.
4. Call `remove_liquidity` on P to recover the donation pro-rata. The position is left under-collateralized at true prices; repayment is skipped, leaving bad debt.

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

**File:** contracts/price-aggregator/src/validation.rs (L120-135)
```rust
fn aquarius_lp_shape(env: &Env, lp: &AquariusLpSource) {
    if ![lp.reserve_a_decimals, lp.reserve_b_decimals]
        .iter()
        .all(|decimals| (MIN_ASSET_DECIMALS..=MAX_ASSET_DECIMALS).contains(decimals))
    {
        panic_with_error!(env, OracleError::InvalidOracleDecimals);
    }
    if lp.token_a == lp.token_b
        || lp.key_a == lp.key_b
        || !key_prices_token(&lp.key_a, &lp.token_a)
        || !key_prices_token(&lp.key_b, &lp.token_b)
        || lp.min_pool_value_wad <= 0
    {
        panic_with_error!(env, OracleError::InvalidOracleBase);
    }
}
```

**File:** contracts/controller/src/risk/totals.rs (L84-97)
```rust
    for (hub_asset, position) in iter_typed_positions(supply_positions) {
        let feed = cache.cached_price(&hub_asset.asset);
        let market_index = cache.cached_market_index(&hub_asset);

        let value = position_value_floor(
            env,
            position.scaled_amount,
            market_index.supply_index,
            feed.price,
        );

        let effective_ltv = position.loan_to_value.min(position.liquidation_threshold);
        ltv = ltv.checked_add(env, effective_ltv.apply_to_wad_floor(env, value));
    }
```

**File:** contracts/controller/src/context.rs (L142-160)
```rust
    pub(crate) fn fetch_prices(&mut self, assets: &Vec<Address>) {
        let missing = collect_uncached_keys(&self.env, assets, &self.token_prices);
        if missing.is_empty() {
            return;
        }
        let fetched = external::price_aggregator::fetch_prices(&self.env, &missing);
        for (asset, feed) in fetched.iter() {
            self.token_prices.set(asset, feed);
        }
    }

    /// Returns a previously loaded price; fails if the cache has no entry.
    pub(crate) fn cached_price(&mut self, asset: &Address) -> PriceFeed {
        let raw = self
            .token_prices
            .get(asset.clone())
            .unwrap_or_else(|| panic_with_error!(&self.env, OracleError::OracleNotConfigured));
        (&raw).into()
    }
```
