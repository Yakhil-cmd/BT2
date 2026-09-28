### Title
Stale fundamental oracle leg inflates blended collateral price and enables undercollateralized borrows - (File: contracts/price-aggregator/src/engine.rs)

### Summary
A two-source oracle can blend a current market price with an anchor observation that is nearly a day old but still below its configured staleness limit. Because `MAX_LEG_AGE_SPREAD_SECONDS` applies only when both legs are classified as `FeedNature::Market`, a stale `Fundamental` anchor bypasses the cross-leg freshness check and contributes its obsolete price to the midpoint. A borrower can use the inflated collateral value through `Controller::borrow`, leaving the protocol with debt above the borrow’s true collateral capacity. Severity: High.

### Finding Description
`read_source` marks a leg stale only when its own observation exceeds the source limit or the oracle-wide `max_price_stale_seconds`. [1](#0-0)  For a two-leg result, `blend` applies the one-hour timestamp-spread check only when both legs have `FeedNature::Market`; a `Fundamental` anchor can therefore be many hours behind the primary without making the result stale. [2](#0-1)  If the two prices remain inside the configured tolerance, the aggregator returns their midpoint. [3](#0-2) 

The controller then uses that accepted midpoint as collateral value in `calculate_account_risk_totals`. [4](#0-3)  `process_borrow` performs the pool borrow before enforcing `ltv_collateral >= total_debt`, so the inflated price directly increases the borrow amount admitted by the final solvency gate. [5](#0-4) [6](#0-5) 

### Impact Explanation
An unprivileged borrower can extract pool liquidity using collateral whose protocol valuation is inflated by a stale anchor. In the demonstrated configuration, the primary reports `$0.91`, while a 23-hour-old `$1.00` fundamental anchor remains accepted under an 86,400-second staleness limit and a 10% tolerance. The accepted midpoint is `$0.955`, inflating collateral and borrow capacity by roughly 4.95% over the fresh-price control. The attacker can call `borrow(caller, account_id, [(debt_hub_asset, 70_000)], to)` after supplying collateral, withdraw the borrowed tokens, and leave an undercollateralized position that may become bad debt.

### Likelihood Explanation
The exploit requires a configured dual-source market with a slow or `Fundamental` secondary leg, a delay or freeze inside that leg’s permitted staleness window, and enough market movement to make the stale price economically material while still passing the tolerance band. Those conditions are plausible during a feed outage or delayed heartbeat and require no privileged role, leaked key, or malicious oracle signature; the attacker merely times an ordinary `borrow` while the obsolete observation remains accepted. The focused test shows the stale case succeeds while the fresh-anchor control reverts with `InsufficientCollateral`. [7](#0-6) 

### Recommendation
Reject blended prices whenever the leg timestamps differ by more than `MAX_LEG_AGE_SPREAD_SECONDS`, regardless of `FeedNature`, or introduce a stricter bound specifically for fundamental anchors that participate in market valuation. Additionally cap each source’s `max_stale_seconds` to its actual publication cadence and consider falling back to a conservative extremum rather than midpoint when one leg is materially older. The final accepted price should not combine observations from materially different market epochs.

### Proof of Concept
1. Configure collateral `XLM` with two sources: fresh Reflector primary and RedStone anchor classified `FeedNature::Fundamental`, using a 10% tolerance and an 86,400-second anchor staleness window.
2. Initially set both observations to `$1.00`.
3. Move the primary to the current price `$0.91`, while leaving the anchor at `$1.00` with timestamp `now - 82_800`.
4. Supply `100,000 XLM` to the attacker’s account.
5. Call `Controller::borrow` for `70,000 USDC`.
6. The stale-anchor run inflates reported collateral by more than 4% and succeeds; the fresh-anchor control rejects the same borrow with `InsufficientCollateral`. [8](#0-7) [7](#0-6)

### Citations

**File:** contracts/price-aggregator/src/engine.rs (L414-438)
```rust
fn blend(env: &Env, oracle: &AssetOracle, legs: Legs) -> Outcome {
    match legs {
        Legs::Empty => Outcome::unreadable(),
        Legs::One(r) => Outcome::one(r),
        Legs::Partial { reading, slot } => Outcome::partial(reading, slot),
        Legs::Two { primary, anchor } => {
            let spread_bounded =
                primary.nature == FeedNature::Market && anchor.nature == FeedNature::Market;
            let age_spread = primary.timestamp.abs_diff(anchor.timestamp);
            let stale = primary.stale
                || anchor.stale
                || (spread_bounded && age_spread > MAX_LEG_AGE_SPREAD_SECONDS);
            let ts = primary.timestamp.min(anchor.timestamp);
            let deviation =
                !within_tolerance_band(env, anchor.price_wad, primary.price_wad, &oracle.tolerance);

            let price_wad = midpoint_price_or_zero(anchor.price_wad, primary.price_wad);
            Outcome {
                price_wad,
                timestamp: ts,
                first_wad: primary.price_wad,
                second_wad: anchor.price_wad,
                stale,
                deviation,
                err: None,
```

**File:** contracts/price-aggregator/src/engine.rs (L539-567)
```rust
/// Evaluates `source` into a `Reading`, if it produces one. Combines the
/// source's own component-level staleness with staleness computed against
/// `oracle.max_price_stale_seconds`.
fn read_source(
    session: &mut Session,
    key: &PriceKey,
    oracle: &AssetOracle,
    source: &PriceSource,
    depth: u32,
) -> Result<Option<Reading>, OracleError> {
    let Some((observation, component_stale)) =
        evaluate_source(session, key, source, oracle.asset_decimals, depth)?
    else {
        return Ok(None);
    };
    let timestamp = observation.timestamp;
    let stale = component_stale
        || is_stale(
            session.now_secs(),
            timestamp,
            oracle.max_price_stale_seconds,
        );
    Ok(Some(Reading {
        price_wad: observation.price_wad,
        timestamp,
        stale,
        nature: source_nature(source),
    }))
}
```

**File:** contracts/price-aggregator/src/tolerance.rs (L9-35)
```rust
/// Returns whether the ratio `larger * BPS / smaller` of `anchor` and
/// `primary`, rounded half up, is at most `tolerance.upper_ratio_bps`
/// (`10_500` allows a 5% gap). Returns `false` when the smaller value is not
/// positive or the ratio overflows `i128`.
pub(crate) fn within_tolerance_band(
    env: &Env,
    anchor: i128,
    primary: i128,
    tolerance: &OracleTolerance,
) -> bool {
    let high = anchor.max(primary);
    let low = anchor.min(primary);
    let Some(upper_ratio_bps) = fp_core::try_mul_div_half_up(env, high, BPS, low) else {
        return false;
    };

    upper_ratio_bps <= i128::from(tolerance.upper_ratio_bps)
}

/// Returns the average of `anchor_price` and `primary_price`, truncated
/// toward zero. Returns `0` if the sum overflows `i128`.
pub(crate) fn midpoint_price_or_zero(anchor_price: i128, primary_price: i128) -> i128 {
    anchor_price
        .checked_add(primary_price)
        .map(|sum| sum / 2)
        .unwrap_or(0)
}
```

**File:** contracts/controller/src/risk/totals.rs (L171-197)
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
```

**File:** contracts/controller/src/positions/debt.rs (L33-65)
```rust
pub(crate) fn process_borrow(
    env: &Env,
    caller: &Address,
    account_id: u64,
    borrows: &Vec<HubPayment>,
    to: Option<Address>,
) {
    validation::require_authorized_caller(env, caller);

    let mut account = storage::get_account(env, account_id);
    require_owner_or_delegate(env, account_id, caller, &account.owner);

    let recipient = to.unwrap_or_else(|| caller.clone());
    let mut cache = Context::new(env);
    require_external_recipient(env, &mut cache, &recipient);
    let aggregated = payments::aggregate_positive_payments(env, borrows);

    validate_position_entry_gates(
        env,
        &account,
        &aggregated,
        &mut cache,
        AccountPositionType::Borrow,
    );
    settle_borrow(env, &mut account, &recipient, &aggregated, &mut cache);

    let restamped = enforce_post_pool_solvency(env, &mut cache, &mut account);
    let sides = if restamped {
        PositionSides::Both
    } else {
        PositionSides::Debt
    };
    finalize_position_flow(env, account_id, &account, &mut cache, sides, false);
```

**File:** contracts/controller/src/risk/validation.rs (L27-53)
```rust
/// Requires debt coverage by LTV-weighted collateral, health factor >= 1, and
/// the configured collateral floor. Debt-free accounts skip all three checks.
pub(crate) fn require_post_pool_risk_gates(env: &Env, cache: &mut Context, account: &Account) {
    if account.debt_free() {
        return;
    }

    let totals = risk::calculate_account_risk_totals(
        env,
        cache,
        &account.supply_positions,
        &account.borrow_positions,
    );

    assert_with_error!(
        env,
        totals.ltv_collateral >= totals.total_debt,
        CollateralError::InsufficientCollateral
    );

    spec_hooks::solvency_gate_checked(account);

    assert_with_error!(
        env,
        totals.health_factor >= Wad::ONE,
        CollateralError::InsufficientCollateral
    );
```

**File:** tests/test-harness/tests/controller/audit_borrow_withdraw_liquidate_stale_anchor_blend.rs (L45-63)
```rust
    t.set_price("XLM", TRUE_FRESH_PRICE);

    let redstone_client = MockRedStonePriceFeedClient::new(&t.env, &redstone);
    let now = t.env.ledger().timestamp();
    if anchor_stale {
        let stale_ms = now.saturating_sub(ANCHOR_LAG_SECONDS) * 1000;
        redstone_client.set_price_data(&feed_id, &ANCHOR_FROZEN_PRICE, &stale_ms, &stale_ms);
    } else {
        let fresh_ms = now * 1000;
        redstone_client.set_price_data(&feed_id, &TRUE_FRESH_PRICE, &fresh_ms, &fresh_ms);
    }

    t.supply(BOB, "USDC", 500_000.0);

    t.supply(ALICE, "XLM", XLM_SUPPLY);

    let collateral_usd = t.total_collateral(ALICE);
    let borrow = t.try_borrow(ALICE, "USDC", TARGET_BORROW);

```

**File:** tests/test-harness/tests/controller/audit_borrow_withdraw_liquidate_stale_anchor_blend.rs (L70-94)
```rust
#[test]
fn audit_borrow_withdraw_liquidate_stale_anchor_blends_5pct_skew_into_ltv() {
    let exploit = run(true);
    let control = run(false);

    let inflation = exploit.collateral_usd / control.collateral_usd;
    assert!(
        inflation > 1.04,
        "stale-anchor blend must inflate collateral >4% vs the honest fresh-anchor \
         valuation: exploit={} control={} ratio={}",
        exploit.collateral_usd,
        control.collateral_usd,
        inflation
    );

    assert!(
        exploit.borrow.is_ok(),
        "stale-anchor skew must let the attacker borrow beyond true capacity: {:?}",
        exploit.borrow
    );

    // Pin the reason: an unrelated fixture break that reverts for any other
    // cause would otherwise "prove" the stale anchor enabled the borrow.
    assert_contract_error(control.borrow, errors::INSUFFICIENT_COLLATERAL);
}
```
