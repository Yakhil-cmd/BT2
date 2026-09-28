### Title
Stale fundamental oracle leg inflates collateral and permits undercollateralized borrows - (File: contracts/price-aggregator/src/engine.rs)

### Summary
A dual-source oracle can blend a fresh market price with a stale `Fundamental` feed that remains within the configured price tolerance. Because the timestamp-spread check applies only when both legs are `Market`, a stale anchor can shift the midpoint valuation upward and let an unprivileged account owner borrow more than the collateral’s current value supports. [1](#0-0) 

### Finding Description
`blend` marks a two-leg result stale when either leg exceeds its configured staleness bound, or when the timestamp spread exceeds `MAX_LEG_AGE_SPREAD_SECONDS`. The spread check is conditioned on both legs having `FeedNature::Market`, so a stale `Fundamental` anchor can be arbitrarily older than the fresh primary leg without triggering the spread bound. [2](#0-1) 

If both quoted prices remain inside the oracle tolerance band, the result is accepted and set to their midpoint rather than the conservative lower leg or current market leg. [3](#0-2) 

The controller’s `borrow` entrypoint is reachable by the account owner or delegate, delegates valuation to the cached strict aggregator prices, performs the pool borrow, and then checks post-borrow solvency. [4](#0-3) [5](#0-4) 

`MAX_LEG_AGE_SPREAD_SECONDS` is 3,600 seconds, but its comment explicitly limits it to two market-nature legs; this leaves mixed market/fundamental pairs without an equivalent cross-leg freshness bound. [6](#0-5) 

### Impact Explanation
An attacker can supply a collateral asset whose slow fundamental feed still reports an obsolete high price while its fresh market feed has fallen by just under the configured tolerance. The midpoint overstates collateral value, increasing LTV-weighted collateral and borrowing capacity. The attacker then calls `borrow` and withdraws debt assets worth more than the true collateral backing allows.

Repeated or large-scale use leaves bad debt backed by overvalued collateral. Liquidation cannot recover the missing value because the pool has already paid out the borrowed assets, producing protocol insolvency or socialized losses.

The repository’s regression test demonstrates this exact path: a frozen $1.00 anchor and fresh $0.91 market price inflate collateral by more than 4% versus an honest fresh-anchor control and make a 70,000 USDC borrow succeed, while the control fails with `INSUFFICIENT_COLLATERAL`. [7](#0-6) 

### Likelihood Explanation
Likelihood is market- and configuration-dependent. A supported market must use two sources where one is a slower `Fundamental` feed and has a staleness bound long enough to remain readable after the market price moves. The test configuration uses an 86,400-second anchor bound and an 82,800-second lag, which remains accepted. [8](#0-7) [9](#0-8) 

No privileged call, compromised signer, malformed transaction, or direct manipulation of the oracle provider is needed once such a market is configured. The attacker needs only an owned or delegated account and can invoke `supply` followed by `borrow`. [10](#0-9) 

### Recommendation
Apply `MAX_LEG_AGE_SPREAD_SECONDS` to every two-leg blend, not only pairs where both sources are `Market`. Alternatively, define a separate maximum age spread for `Fundamental` legs and mark the outcome stale when exceeded.

For valuation, prefer the more conservative leg—normally the lower price for collateral valuation—or use the freshest source when the legs’ observation ages differ materially. Governance validation should also reject mixed natures whose freshness models are incompatible, or require tighter per-feed `max_stale_seconds` and tolerance when mixing them.

### Proof of Concept
1. Configure an asset with a fresh Reflector `Market` leg and a RedStone `Fundamental` leg, where the RedStone leg has a large `max_stale_seconds` such as 86,400.
2. Set both feeds to $1.00 initially.
3. Move the fresh market feed down to $0.91 while leaving the fundamental feed at $1.00 with an 82,800-second-old timestamp.
4. Supply 100,000 units of the collateral and call `borrow` for 70,000 USDC.
5. The aggregator accepts the midpoint $0.955 because the 9% price difference is within a 10% tolerance and the mixed natures bypass the 3,600-second timestamp-spread check.
6. The borrow succeeds even though the same transaction fails with `INSUFFICIENT_COLLATERAL` when the anchor is fresh at $0.91, as implemented by `audit_borrow_withdraw_liquidate_stale_anchor_blends_5pct_skew_into_ltv`. [11](#0-10)

### Citations

**File:** contracts/price-aggregator/src/engine.rs (L420-438)
```rust
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

**File:** contracts/controller/src/lib.rs (L90-115)
```rust
    /// Supplies `assets` as collateral and returns the account id; `account_id = 0`
    /// creates an account in `spoke_id`. Third parties may only top up existing
    /// supply positions; owners and delegates may add assets.
    #[when_not_paused]
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

**File:** contracts/controller/src/positions/debt.rs (L40-60)
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
    let sides = if restamped {
```

**File:** common/src/oracle/observation.rs (L30-34)
```rust
/// Largest timestamp gap between two market-nature legs of a blended price
/// before the blend is marked stale.
///
/// A TWAP leg carries the timestamp of the oldest sample in its window.
pub const MAX_LEG_AGE_SPREAD_SECONDS: u64 = 3_600;
```

**File:** tests/test-harness/tests/controller/audit_borrow_withdraw_liquidate_stale_anchor_blend.rs (L7-9)
```rust
const XLM_TOLERANCE_BPS: u32 = 1000;
const ANCHOR_MAX_STALE_SECONDS: u64 = 86_400;
const ANCHOR_LAG_SECONDS: u64 = 82_800;
```

**File:** tests/test-harness/tests/controller/audit_borrow_withdraw_liquidate_stale_anchor_blend.rs (L34-62)
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
