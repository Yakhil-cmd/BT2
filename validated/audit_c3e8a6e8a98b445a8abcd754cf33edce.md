### Title

Mixed-nature dual-source prices bypass the age-spread bound and blend stale prices into lending valuations - (File: contracts/price-aggregator/src/engine.rs)

### Summary

A dual-source oracle composed of a market-nature leg and a fundamental-nature leg can accept arbitrarily separated observation timestamps, provided each leg remains within its own staleness window, because the cross-leg age-spread check only applies when both legs are `FeedNature::Market`. [1](#0-0)  The accepted result is the midpoint of the fresh market price and the stale fundamental price, so an old price can shift the controller's collateral and debt valuations by up to roughly half the configured tolerance band. [2](#0-1) 

### Finding Description

`compose` reads up to two configured sources and passes both successful readings to `blend`. [3](#0-2)  Each source is marked stale only when its provider-level window or the oracle-level `max_price_stale_seconds` is exceeded. [4](#0-3)  When two readings exist, the additional timestamp-spread rejection is skipped if either leg is `Fundamental`, and the two prices are averaged anyway. [5](#0-4) 

Reflector sources are always classified as `Market`, while RedStone sources can be configured as `Fundamental`. [6](#0-5)  The mainnet XLM configuration pairs a one-hour Reflector TWAP source with a 46,800-second RedStone `Fundamental` source under a 57,600-second asset ceiling and a 110% upper tolerance ratio. [7](#0-6)  Therefore, the RedStone leg can be many hours older than the market leg and still contribute half of the final price.

The controller fetches this blended price through `fetch_prices` and caches it in the operation context. [8](#0-7) [9](#0-8)  Borrow and liquidation risk calculations directly multiply scaled collateral and debt positions by `feed.price`, so the stale-leg midpoint becomes the authoritative risk valuation. [10](#0-9) 

### Impact Explanation

An unprivileged borrower can use a stale high-priced anchor to inflate collateral and borrow more pool assets than the fresh market price supports through `borrow(caller, account_id, borrows, to)`. [11](#0-10)  A stale low-priced anchor can instead deflate collateral, make an account that remains solvent at the fresh market price appear liquidatable, and let an unprivileged liquidator seize discounted collateral through `liquidate(liquidator, account_id, debt_payments, SeizeMode::Transfer)`. [12](#0-11) 

The repository's regression test demonstrates the high-price direction: an 82,800-second-old anchor at `$1.00` is averaged with a fresh `$0.91` primary, inflating reported collateral by more than 4% and allowing a `$70,000` borrow that the fresh-anchor control rejects as undercollateralized. [13](#0-12) [14](#0-13)  In the opposite direction, the same midpoint behavior transfers borrower equity to a liquidator by valuing seized collateral below its current market price.

### Likelihood Explanation

The condition only requires an ordinary missed or slow update on a configured `Fundamental` leg while the market leg moves within the configured tolerance band; it does not require oracle compromise or privileged access. [15](#0-14)  The deployed XLM oracle permits the lagging RedStone leg to remain valid for 46,800 seconds, while the mixed-nature check removes the one-hour cross-leg bound that would otherwise reject such a pair. [16](#0-15) [17](#0-16) 

### Recommendation

Apply `MAX_LEG_AGE_SPREAD_SECONDS` to all dual-source blends, or cap the timestamp difference by the tighter of the two source staleness budgets, regardless of declared `FeedNature`. [18](#0-17)  If slow fundamental anchors must remain valid, do not midpoint them directly into risk-bearing collateral valuation: use the conservative leg for the relevant direction, such as the lower price for collateral and the higher price for debt, or mark the blend unusable once the timestamp gap exceeds the market leg's freshness horizon. [19](#0-18) 

### Proof of Concept

1. Use a dual-source market with a Reflector market leg and a RedStone `Fundamental` leg, such as the mainnet XLM shape. [20](#0-19) 
2. Leave RedStone at an old `$1.00` observation while Reflector reports a fresh `$0.91`; with a 110% tolerance ratio, the legs are close enough to pass deviation checking. [21](#0-20) 
3. `blend` accepts the pair because the RedStone leg is `Fundamental`, skips the age-spread rejection, and returns approximately `$0.955` instead of rejecting the stale comparison or using the fresh price. [22](#0-21) 
4. Call `supply` to create an attacker-owned account with the affected collateral, then call `borrow` for the debt asset; the post-borrow gate evaluates the inflated midpoint price through `calculate_account_risk_totals`. [23](#0-22) [24](#0-23) 
5. The checked-in harness executes this exact scenario and shows the stale-anchor run borrowing successfully while the fresh-anchor control reverts with `InsufficientCollateral`. [14](#0-13)

### Citations

**File:** contracts/price-aggregator/src/engine.rs (L419-436)
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
```

**File:** contracts/price-aggregator/src/engine.rs (L499-526)
```rust
    let count = oracle.sources.len();
    if count == 0 || count > 2 {
        return Err(OracleError::SourceCountOutOfRange);
    }

    let first = read_source(
        session,
        key,
        oracle,
        &oracle.sources.get_unchecked(0),
        depth,
    )?;
    if count == 1 {
        return Ok(match first {
            Some(r) => Legs::One(r),
            None => Legs::Empty,
        });
    }

    let second = read_source(
        session,
        key,
        oracle,
        &oracle.sources.get_unchecked(1),
        depth,
    )?;
    Ok(match (first, second) {
        (Some(primary), Some(anchor)) => Legs::Two { primary, anchor },
```

**File:** contracts/price-aggregator/src/engine.rs (L549-560)
```rust
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

**File:** contracts/price-aggregator/src/tolerance.rs (L13-25)
```rust
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
```

**File:** contracts/price-aggregator/src/tolerance.rs (L28-34)
```rust
/// Returns the average of `anchor_price` and `primary_price`, truncated
/// toward zero. Returns `0` if the sum overflows `i128`.
pub(crate) fn midpoint_price_or_zero(anchor_price: i128, primary_price: i128) -> i128 {
    anchor_price
        .checked_add(primary_price)
        .map(|sum| sum / 2)
        .unwrap_or(0)
```

**File:** common/src/types/composable_oracle.rs (L38-55)
```rust
/// Classifies a feed as tracking a live market price or a slower-moving fundamental value.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FeedNature {
    Market,

    Fundamental,
}

/// References a feed on a RedStone or Xoxno multi-feed provider contract, identified by
/// feed ID, together with its `FeedNature`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MultiFeedRef {
    pub contract: Address,
    pub feed_id: String,
    pub nature: FeedNature,
}
```

**File:** common/src/types/composable_oracle.rs (L86-93)
```rust
    /// Returns the feed's nature. Reflector references are always `Market`; RedStone and
    /// Xoxno references carry an explicit `FeedNature`.
    pub fn nature(&self) -> FeedNature {
        match self {
            ProviderRef::Reflector(_) => FeedNature::Market,
            ProviderRef::RedStone(r) | ProviderRef::Xoxno(r) => r.nature,
        }
    }
```

**File:** configs/mainnet/markets.json (L60-96)
```json
        "asset_decimals": 7,
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

**File:** contracts/controller/src/risk/totals.rs (L157-166)
```rust
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
```

**File:** contracts/controller/src/risk/totals.rs (L171-201)
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

    let total_debt = sum_debt_usd_loaded(env, cache, borrow_positions, position_value_ceil);
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

**File:** contracts/controller/src/lib.rs (L136-158)
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

**File:** common/src/oracle/observation.rs (L30-34)
```rust
/// Largest timestamp gap between two market-nature legs of a blended price
/// before the blend is marked stale.
///
/// A TWAP leg carries the timestamp of the oldest sample in its window.
pub const MAX_LEG_AGE_SPREAD_SECONDS: u64 = 3_600;
```
