### Title
Permitted stale oracle leg inflates collateral through midpoint pricing - (File: contracts/price-aggregator/src/engine.rs)

### Summary
A dual-source oracle can blend a fresh primary price with an old secondary price and return their midpoint whenever both prices remain inside the configured tolerance band. [1](#0-0)  An unprivileged borrower can use that inflated collateral valuation through the public `supply` and `borrow` entrypoints to take debt above the economically safe amount, leaving later liquidation or bad-debt cleanup to socialize the shortfall. [2](#0-1) [3](#0-2) 

### Finding Description
`blend` computes a two-source `age_spread`, but only enforces the cross-source age limit when both legs have `FeedNature::Market`; otherwise the stale result depends solely on each source’s independent staleness window. [4](#0-3)  Each feed separately marks itself stale against its own `max_stale_seconds`, so a permitted non-market or long-window anchor can remain valid long after the primary has moved. [5](#0-4)  If the old anchor and fresh primary stay within tolerance, the engine accepts the pair and publishes their integer midpoint instead of using the fresh leg or rejecting the observation. [6](#0-5) [7](#0-6) 

The controller caches this strict aggregator output for the transaction and uses it to calculate collateral and debt values. [8](#0-7)  `process_borrow` mints pool debt before calling the post-pool gates, and those gates only compare the oracle-valued LTV collateral and health factor against the recorded debt. [9](#0-8) [10](#0-9)  Consequently, a stale-high collateral leg shifts the accepted midpoint upward and permits borrowing that would revert when both legs reflect the fresh price. [11](#0-10) 

### Impact Explanation
This can create protocol insolvency because the borrower receives real pool cash while the collateral’s accepted value is inflated by roughly half of the tolerated primary-anchor discrepancy. [12](#0-11) [7](#0-6)  The regression test demonstrates a fresh `$0.91` primary blended with a 23-hour-old `$1.00` anchor into an approximately `$0.955` valuation, increasing measured collateral by more than 4% and making a `$70,000` borrow succeed where an honest fresh-anchor control fails collateral checks. [13](#0-12) [14](#0-13)  Once the stale anchor converges downward or the position is liquidated, the excess borrowed USD can exceed recoverable collateral and residual debt can be socialized through `clean_bad_debt`. [3](#0-2) 

### Likelihood Explanation
The attack needs no privileged call: after a price move creates a still-tolerated gap between a fresh leg and a permitted stale leg, the attacker supplies that collateral and calls `borrow`. [2](#0-1)  The condition is realistic for configurations that pair providers with materially different freshness windows or natures, because `source_nature` controls whether the cross-leg age-spread check is applied at all. [15](#0-14) [16](#0-15)  The included test reaches the state with an anchor lag of `82,800` seconds under an `86,400`-second limit and a 10% tolerance. [17](#0-16) 

### Recommendation
Apply the dual-leg timestamp-spread limit to every two-source oracle, not only pairs where both legs are `Market`, and fail closed when a mixed-source pair is too old relative to the fresh leg. [4](#0-3)  For collateral valuation, consider using the lower accepted leg rather than the midpoint, while retaining the existing tolerance and sanity-bound rejection for disagreement. [18](#0-17) [19](#0-18)  Governance should also align per-source `max_stale_seconds` values so an anchor cannot remain valid across a price move approaching the tolerance width. [20](#0-19) 

### Proof of Concept
The production path is `Controller::supply(attacker, 0, spoke_id, [(XLM, amount)])` followed by `Controller::borrow(attacker, account_id, [(USDC, borrow_amount)], attacker)`. [2](#0-1) 

```rust
// Existing regression: tests/test-harness/tests/controller/
// audit_borrow_withdraw_liquidate_stale_anchor_blend.rs

const ANCHOR_FROZEN_PRICE: i128 = usd(1);
const TRUE_FRESH_PRICE: i128 = usd_cents(91);
const XLM_TOLERANCE_BPS: u32 = 1000;
const ANCHOR_MAX_STALE_SECONDS: u64 = 86_400;
const ANCHOR_LAG_SECONDS: u64 = 82_800;
const XLM_SUPPLY: f64 = 100_000.0;
const TARGET_BORROW: f64 = 70_000.0;

// Primary XLM price is updated to $0.91.
// Secondary remains valid at $1.00 with a timestamp 82,800 seconds old.
// Aggregator output becomes approximately $0.955.
t.supply(BOB, "USDC", 500_000.0);
t.supply(ALICE, "XLM", XLM_SUPPLY);
let borrow = t.try_borrow(ALICE, "USDC", TARGET_BORROW);
assert!(borrow.is_ok());
```

The same test’s fresh-anchor control reports the correct lower collateral value and rejects the identical `$70,000` borrow with `INSUFFICIENT_COLLATERAL`, isolating the stale-anchor midpoint as the enabling condition. [14](#0-13)

### Citations

**File:** contracts/price-aggregator/src/engine.rs (L133-145)
```rust
        if self.stale {
            return Some(OracleError::PriceFeedStale);
        }
        if self.deviation {
            return Some(OracleError::UnsafePriceNotAllowed);
        }
        if self.price_wad <= 0 {
            return Some(OracleError::InvalidPrice);
        }
        if self.price_wad < oracle.min_sanity_price_wad
            || self.price_wad > oracle.max_sanity_price_wad
        {
            return Some(OracleError::SanityBoundViolated);
```

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

**File:** contracts/price-aggregator/src/engine.rs (L539-560)
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
```

**File:** contracts/price-aggregator/src/engine.rs (L561-566)
```rust
    Ok(Some(Reading {
        price_wad: observation.price_wad,
        timestamp,
        stale,
        nature: source_nature(source),
    }))
```

**File:** contracts/price-aggregator/src/engine.rs (L573-578)
```rust
fn source_nature(source: &PriceSource) -> FeedNature {
    match source {
        PriceSource::Feed(feed) => feed.provider.nature(),
        PriceSource::Scaled(scaled) => scaled.factor.provider.nature(),
        PriceSource::AquariusLp(_) | PriceSource::AquariusStableLp(_) => FeedNature::Market,
    }
```

**File:** contracts/price-aggregator/src/engine.rs (L613-617)
```rust
    let stale = is_stale(
        session.now_secs(),
        observation.timestamp,
        feed.max_stale_seconds,
    );
```

**File:** contracts/controller/src/lib.rs (L93-114)
```rust
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
```

**File:** contracts/controller/src/lib.rs (L136-164)
```rust
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
    }

    /// Socializes insolvent debt into the supply index and removes the account
    /// when remaining collateral is at or below the dust cap. Permissionless;
    /// requires caller authorization.
    fn clean_bad_debt(env: Env, caller: Address, account_id: u64) {
        positions::liquidation::process_clean_bad_debt(&env, &caller, account_id);
```

**File:** contracts/price-aggregator/src/tolerance.rs (L30-34)
```rust
pub(crate) fn midpoint_price_or_zero(anchor_price: i128, primary_price: i128) -> i128 {
    anchor_price
        .checked_add(primary_price)
        .map(|sum| sum / 2)
        .unwrap_or(0)
```

**File:** contracts/controller/src/context.rs (L141-150)
```rust
    /// Fetches missing prices in one aggregator call; retains cached prices.
    pub(crate) fn fetch_prices(&mut self, assets: &Vec<Address>) {
        let missing = collect_uncached_keys(&self.env, assets, &self.token_prices);
        if missing.is_empty() {
            return;
        }
        let fetched = external::price_aggregator::fetch_prices(&self.env, &missing);
        for (asset, feed) in fetched.iter() {
            self.token_prices.set(asset, feed);
        }
```

**File:** contracts/controller/src/positions/debt.rs (L50-59)
```rust
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

**File:** contracts/controller/src/positions/debt.rs (L101-110)
```rust
    let pool_addr = cache.cached_pool_address();
    let mut entries: Vec<PoolBorrowEntry> = Vec::new(env);
    for (hub_asset, amount) in aggregated.iter() {
        let position = account.get_or_create_debt_position(&hub_asset);
        entries.push_back(PoolBorrowEntry {
            action: make_pool_action(&position, amount, hub_asset.clone()),
        });
    }
    let results = pool_borrow_call(env, &pool_addr, recipient, &entries);
    for_each_leg(env, &entries, &results, |entry, result| {
```

**File:** contracts/controller/src/risk/validation.rs (L41-52)
```rust
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
```

**File:** tests/test-harness/tests/controller/audit_borrow_withdraw_liquidate_stale_anchor_blend.rs (L5-13)
```rust
const ANCHOR_FROZEN_PRICE: i128 = usd(1);
const TRUE_FRESH_PRICE: i128 = usd_cents(91);
const XLM_TOLERANCE_BPS: u32 = 1000;
const ANCHOR_MAX_STALE_SECONDS: u64 = 86_400;
const ANCHOR_LAG_SECONDS: u64 = 82_800;

const XLM_SUPPLY: f64 = 100_000.0;

const TARGET_BORROW: f64 = 70_000.0;
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
