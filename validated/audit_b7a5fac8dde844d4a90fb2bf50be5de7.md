### Title
Stale oracle anchor is blended into collateral valuation, enabling undercollateralized borrowing - (`contracts/price-aggregator/src/engine.rs`)

### Summary
A dual-source oracle averages a fresh market leg with a still-accepted stale fundamental leg, without enforcing cross-leg timestamp freshness unless both legs are market feeds. [1](#0-0)  An attacker can use the resulting inflated collateral value through `Controller::borrow`, then retain the borrowed assets after the stale leg corrects. [2](#0-1) 

### Finding Description
`blend` marks a two-source outcome stale for individual leg staleness, but applies the `MAX_LEG_AGE_SPREAD_SECONDS` check only when both sources have `FeedNature::Market`. [3](#0-2)  When the stale leg is `Fundamental`, a large observation-age gap is ignored and the accepted price is the midpoint of the fresh and stale prices. [4](#0-3)  Oracle configuration permits a source and asset staleness envelope as large as 93,600 seconds. [5](#0-4) [6](#0-5)  The controller accepts this blended price while proving post-borrow LTV coverage and health factor, so the inflated midpoint directly increases borrowing capacity. [7](#0-6) 

### Impact Explanation
The borrower can draw debt that is solvent only under the stale-anchor midpoint and becomes undercollateralized when the anchor reflects the current price. [8](#0-7)  Liquidation cannot necessarily recover the full borrowed value after correction, and residual debt can be socialized through the bad-debt path, transferring the loss to suppliers. [9](#0-8) [10](#0-9) 

### Likelihood Explanation
The exploit needs only a normally reachable collateral supply followed by `borrow(caller, account_id, borrows, to)` while one configured anchor is old but still inside its accepted staleness bound. [2](#0-1)  The regression case demonstrates a 82,800-second-old RedStone anchor being accepted under an 86,400-second bound and blended with a fresh $0.91 Reflector observation. [11](#0-10)  That configuration produces more than 4% collateral inflation and turns an otherwise rejected $70,000 borrow into a successful one. [8](#0-7) 

### Recommendation
Apply the dual-leg timestamp-spread rejection to all feed natures, not only `Market`-`Market` pairs, or reject a leg whose age materially exceeds the fresher leg's observation window. [1](#0-0)  Prefer the conservative leg for collateral valuation instead of averaging observations with materially different timestamps. [12](#0-11) 

### Proof of Concept
The existing deterministic regression configures Reflector TWAP plus a RedStone anchor, moves the live price from $1.00 to $0.91, and leaves the RedStone observation 82,800 seconds old under an 86,400-second source limit. [11](#0-10)  It supplies 500,000 USDC liquidity, supplies 100,000 XLM to the attacker account, and submits `try_borrow(ALICE, "USDC", 70_000)`. [13](#0-12)  The stale-anchor run inflates collateral by more than 4% and succeeds, while the fresh-anchor control fails with `InsufficientCollateral`. [8](#0-7)

### Citations

**File:** contracts/price-aggregator/src/engine.rs (L419-438)
```rust
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

**File:** contracts/controller/src/positions/debt.rs (L40-59)
```rust
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
```

**File:** common/src/oracle/observation.rs (L17-21)
```rust
pub const MIN_PRICE_STALE_SECONDS: u64 = 60;
/// Largest staleness budget an oracle may declare (26 h). It exceeds the 24 h
/// heartbeat of the slowest consumed feed, so a feed that publishes only on its
/// heartbeat does not read as stale.
pub const MAX_PRICE_STALE_SECONDS: u64 = 93_600;
```

**File:** contracts/price-aggregator/src/validation.rs (L44-52)
```rust
pub(crate) fn staleness_envelope(
    env: &Env,
    asset_max_stale_seconds: u64,
    properties: &SourceProperties,
) {
    if !(MIN_PRICE_STALE_SECONDS..=MAX_PRICE_STALE_SECONDS).contains(&asset_max_stale_seconds)
        || properties.loosest_max_stale_seconds > asset_max_stale_seconds
    {
        panic_with_error!(env, OracleError::InvalidStalenessConfig);
```

**File:** contracts/controller/src/risk/validation.rs (L34-58)
```rust
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

    let floor = storage::get_min_borrow_collateral_usd_wad(env);
    if floor != 0 && totals.ltv_collateral.raw() < floor {
        panic_with_error!(env, CollateralError::MinBorrowCollateralNotMet);
    }
```

**File:** tests/test-harness/tests/controller/audit_borrow_withdraw_liquidate_stale_anchor_blend.rs (L34-55)
```rust
    let cfg = test_harness::reflector_primary_redstone_anchor_config_with_anchor_stale(
        &t.env,
        &t.mock_reflector,
        &xlm,
        &redstone,
        &feed_id,
        ANCHOR_MAX_STALE_SECONDS,
        XLM_TOLERANCE_BPS,
    );
    t.configure_market_oracle(&xlm, &cfg);

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
```

**File:** tests/test-harness/tests/controller/audit_borrow_withdraw_liquidate_stale_anchor_blend.rs (L57-63)
```rust
    t.supply(BOB, "USDC", 500_000.0);

    t.supply(ALICE, "XLM", XLM_SUPPLY);

    let collateral_usd = t.total_collateral(ALICE);
    let borrow = t.try_borrow(ALICE, "USDC", TARGET_BORROW);

```

**File:** tests/test-harness/tests/controller/audit_borrow_withdraw_liquidate_stale_anchor_blend.rs (L70-93)
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
```

**File:** contracts/controller/src/positions/liquidation/mod.rs (L135-137)
```rust
    apply::check_bad_debt_after_liquidation(env, &mut cache, account_id, &account, &post_totals);

    receiver.map_or(0, |(id, _)| id)
```

**File:** contracts/controller/src/positions/liquidation/mod.rs (L240-248)
```rust
/// Socializes insolvent debt when remaining collateral is at or below the dust cap.
pub(crate) fn clean_bad_debt_standalone(env: &Env, account_id: u64) {
    socialize_bad_debt(env, account_id, BadDebtGate::DustCapped);
}

/// Socializes debt exceeding collateral without a dust cap, outside flash loans.
pub(crate) fn process_force_socialize_bad_debt(env: &Env, account_id: u64) {
    validation::require_not_flash_loaning(env);
    socialize_bad_debt(env, account_id, BadDebtGate::InsolventOnly);
```
