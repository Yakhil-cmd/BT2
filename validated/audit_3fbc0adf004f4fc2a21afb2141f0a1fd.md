### Title
Stale fundamental oracle leg can skew the blended collateral price and enable undercollateralized borrows - ([File: contracts/price-aggregator/src/engine.rs](https://github.com/Jaredbentat/rs-lending-xlm--024/blob/main/contracts/price-aggregator/src/engine.rs))

### Summary
The dual-source price aggregator checks each leg only against its own configured staleness window and applies the cross-leg timestamp-spread check only when both sources have `FeedNature::Market`. [1](#0-0)  Consequently, a fresh market leg can be averaged with a much older `Fundamental` leg, moving the accepted midpoint by almost half the configured tolerance while remaining valid. [2](#0-1) 

### Finding Description
Each feed independently becomes stale only when its timestamp is older than that feed's `max_stale_seconds`. [3](#0-2)  A second freshness check applies the asset-level `max_price_stale_seconds`, but configuration validation explicitly permits a source staleness bound as large as that asset-level bound rather than requiring comparable leg freshness. [4](#0-3) [5](#0-4) 

The cross-leg age-spread bound is skipped whenever either leg is `Fundamental`; `source_nature` maps a plain feed to its provider nature and only flags Aquarius sources as `Market`. [1](#0-0) [6](#0-5)  The mainnet XLM oracle uses a 3,600-second Reflector TWAP leg and a 46,800-second RedStone `Fundamental` leg with an 11,000 upper ratio tolerance, so an anchor nearly 13 hours old is not stale under its own leg window and is exempt from the one-hour leg-age spread check. [7](#0-6) 

The aggregator then takes the integer midpoint of both legs rather than rejecting the asynchronous observation set or using the risk-conservative leg. [8](#0-7)  The controller calls the fail-closed `prices` endpoint, caches the resulting `PriceFeedRaw`, and uses it in collateral and debt valuation. [9](#0-8) [10](#0-9)  An unprivileged user can reach this path through `borrow(caller, account_id, borrows, to)`, which delegates to `process_borrow` and requires post-borrow solvency. [11](#0-10)  The solvency check compares LTV-weighted collateral against total debt and requires health factor at least one. [12](#0-11) [13](#0-12) 

### Impact Explanation
If an old anchor price remains above a fresh market price but within the configured ratio tolerance, the midpoint overstates collateral value. [14](#0-13)  At the XLM 10% leg-ratio limit, the blended price can differ from the fresh primary price by roughly 4.8% in the direction of the stale anchor. [15](#0-14)  That inflated valuation can pass `ltv_collateral >= total_debt` even though the fresh market valuation would fail, allowing an account to borrow more than its true collateral capacity and potentially leave the protocol with bad debt. [16](#0-15) 

The same stale-anchor mechanism can affect withdrawals and liquidation-sensitive health factor because both use the common cached price and account-risk totals path. [17](#0-16) 

### Likelihood Explanation
The attacker does not need oracle authorization, governance access, a leaked key, or an invalid parameter write; they only need their own collateral account and must wait for a configured fundamental feed to lag the primary feed while remaining inside its own freshness window and the price tolerance. [18](#0-17)  The deployed XLM configuration makes this materially possible because the two leg freshness windows differ by a factor of 13, while the age-spread protection is disabled by the anchor's `Fundamental` nature. [19](#0-18) [1](#0-0) 

### Recommendation
Apply the leg timestamp-spread check to every two-source blend, regardless of `FeedNature`, or use a separate maximum age difference appropriate for mixed market/fundamental pairs. [20](#0-19)  Alternatively, treat the slower leg solely as a deviation anchor and price the asset from the fresh market leg, or configure freshness windows so the legs cannot differ enough to create material midpoint bias. [2](#0-1)  At minimum, reject dual-source outcomes whose observation timestamps differ beyond `MAX_LEG_AGE_SPREAD_SECONDS` before allowing `prices` to return a blended value to the controller. [21](#0-20) 

### Proof of Concept
The existing live-path regression scenario configures XLM with a fresh Reflector leg and a RedStone anchor permitted to remain 86,400 seconds old. [22](#0-21)  The scenario freezes the anchor at `$1.00`, updates the primary market price to `$0.91`, and ages the anchor by 82,800 seconds, leaving it within its configured staleness window and inside the 10% tolerance ratio. [23](#0-22) 

After BOB supplies 500,000 USDC liquidity, ALICE supplies 100,000 XLM and calls the public `borrow` path for 70,000 USDC. [24](#0-23)  The test demonstrates that the stale-anchor transaction succeeds and inflates measured collateral by more than 4%, while the equivalent fresh-anchor transaction reverts with `INSUFFICIENT_COLLATERAL`. [25](#0-24)

### Citations

**File:** contracts/price-aggregator/src/engine.rs (L419-426)
```rust
        Legs::Two { primary, anchor } => {
            let spread_bounded =
                primary.nature == FeedNature::Market && anchor.nature == FeedNature::Market;
            let age_spread = primary.timestamp.abs_diff(anchor.timestamp);
            let stale = primary.stale
                || anchor.stale
                || (spread_bounded && age_spread > MAX_LEG_AGE_SPREAD_SECONDS);
            let ts = primary.timestamp.min(anchor.timestamp);
```

**File:** contracts/price-aggregator/src/engine.rs (L427-438)
```rust
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

**File:** contracts/price-aggregator/src/engine.rs (L555-560)
```rust
    let stale = component_stale
        || is_stale(
            session.now_secs(),
            timestamp,
            oracle.max_price_stale_seconds,
        );
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

**File:** contracts/price-aggregator/src/engine.rs (L603-618)
```rust
/// Reads `feed` from its provider (Reflector, RedStone, or Xoxno), returning
/// `None` if the provider has no observation. Computes staleness against
/// `feed.max_stale_seconds`.
fn read_feed(session: &mut Session, feed: &FeedSource) -> Option<(OracleObservation, bool)> {
    let observation = match &feed.provider {
        ProviderRef::Reflector(r) => reflector::read_reflector_source(session, r, feed.decimals),
        ProviderRef::RedStone(r) => multi_feed::read_multi_feed_source(session, r, feed.decimals),
        ProviderRef::Xoxno(x) => multi_feed::read_multi_feed_source(session, x, feed.decimals),
    }?;

    let stale = is_stale(
        session.now_secs(),
        observation.timestamp,
        feed.max_stale_seconds,
    );
    Some((observation, stale))
```

**File:** contracts/price-aggregator/src/validation.rs (L44-53)
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
    }
```

**File:** configs/mainnet/markets.json (L61-100)
```json
        "max_price_stale_seconds": 57600,
        "sources": [
          {
            "Feed": {
              "provider": {
                "Reflector": {
                  "contract": "CAFJZQWSED6YAWZU3GWRTOCNPPCGBN32L7QV43XX5LZLFTK6JLN34DLN",
                  "asset": {
                    "Symbol": "XLM"
                  },
                  "read_mode": {
                    "Twap": 3
                  }
                }
              },
              "decimals": 14,
              "max_stale_seconds": 3600
            }
          },
          {
            "Feed": {
              "provider": {
                "RedStone": {
                  "contract": "CA526Y2NQWGWVVQ7RFFPGAZMU66PSYJ3UC2MTVAV4ZU7OM5BOPHDXUSG",
                  "feed_id": "XLM",
                  "nature": "Fundamental"
                }
              },
              "decimals": 8,
              "max_stale_seconds": 46800
            }
          }
        ],
        "tolerance": {
          "upper_ratio_bps": 11000,
          "lower_ratio_bps": 9091
        },
        "independence": "RequireDisjoint",
        "min_sanity_price_wad": "50000000000000000",
        "max_sanity_price_wad": "1000000000000000000"
```

**File:** contracts/price-aggregator/src/tolerance.rs (L19-35)
```rust
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

**File:** contracts/controller/src/external/price_aggregator.rs (L17-28)
```rust
/// Fetches resolved WAD prices; any missing entry fails with `OracleNotConfigured`.
pub(crate) fn fetch_prices(env: &Env, assets: &Vec<Address>) -> Map<Address, PriceFeedRaw> {
    let aggregator = storage::get_price_aggregator(env);
    let keyed = PriceAggregatorClient::new(env, &aggregator).prices(&token_keys(env, assets));
    let mut out = Map::new(env);
    for asset in assets.iter() {
        match keyed.get(PriceKey::Token(asset.clone())) {
            Some(feed) => out.set(asset, feed),
            None => panic_with_error!(env, OracleError::OracleNotConfigured),
        }
    }
    out
```

**File:** contracts/controller/src/context.rs (L141-159)
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
    }

    /// Returns a previously loaded price; fails if the cache has no entry.
    pub(crate) fn cached_price(&mut self, asset: &Address) -> PriceFeed {
        let raw = self
            .token_prices
            .get(asset.clone())
            .unwrap_or_else(|| panic_with_error!(&self.env, OracleError::OracleNotConfigured));
        (&raw).into()
```

**File:** contracts/controller/src/lib.rs (L104-115)
```rust
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

**File:** contracts/controller/src/risk/validation.rs (L27-58)
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

    let floor = storage::get_min_borrow_collateral_usd_wad(env);
    if floor != 0 && totals.ltv_collateral.raw() < floor {
        panic_with_error!(env, CollateralError::MinBorrowCollateralNotMet);
    }
```

**File:** contracts/controller/src/risk/totals.rs (L152-179)
```rust
/// Loads missing market data and values stored position risk snapshots in WAD.
/// Total collateral rounds half-up; collateral used for risk gates and its
/// weights round down, while debt rounds up. Health factor is weighted
/// collateral / debt, floored and saturated at `i128::MAX`; debt-free accounts
/// use `i128::MAX`.
fn calculate_account_risk_totals_body(
    env: &Env,
    cache: &mut Context,
    supply_positions: &Map<HubAssetKey, AccountPositionRaw>,
    borrow_positions: &Map<HubAssetKey, DebtPositionRaw>,
) -> AccountRiskTotals {
    cache.load_markets(&portfolio_hub_keys(
        supply_positions.keys(),
        &borrow_positions.keys(),
    ));

    let mut total_collateral = Wad::ZERO;
    let mut ltv_collateral = Wad::ZERO;
    let mut weighted_collateral = Wad::ZERO;
    for (hub_asset, position) in iter_typed_positions(supply_positions) {
        let feed = cache.cached_price(&hub_asset.asset);
        let market_index = cache.cached_market_index(&hub_asset);

        let value = position_value(
            env,
            position.scaled_amount,
            market_index.supply_index,
            feed.price,
```

**File:** contracts/price-aggregator/src/lib.rs (L69-77)
```rust
    /// Resolves and returns the price feed for each of `keys`, panicking if
    /// any key fails to resolve to a usable price.
    fn prices(env: Env, keys: Vec<PriceKey>) -> Map<PriceKey, PriceFeedRaw> {
        let mut out = Map::new(&env);
        let mut session = warmed_session(&env, &keys);
        for key in keys.iter() {
            out.set(key.clone(), engine::resolve(&mut session, &key, 0));
        }
        out
```

**File:** tests/test-harness/tests/controller/audit_borrow_withdraw_liquidate_stale_anchor_blend.rs (L34-43)
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
```

**File:** tests/test-harness/tests/controller/audit_borrow_withdraw_liquidate_stale_anchor_blend.rs (L45-55)
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
```

**File:** tests/test-harness/tests/controller/audit_borrow_withdraw_liquidate_stale_anchor_blend.rs (L57-63)
```rust
    t.supply(BOB, "USDC", 500_000.0);

    t.supply(ALICE, "XLM", XLM_SUPPLY);

    let collateral_usd = t.total_collateral(ALICE);
    let borrow = t.try_borrow(ALICE, "USDC", TARGET_BORROW);

```

**File:** tests/test-harness/tests/controller/audit_borrow_withdraw_liquidate_stale_anchor_blend.rs (L71-94)
```rust
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
