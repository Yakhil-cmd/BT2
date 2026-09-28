### Title
Lagging oracle anchor is blended into collateral valuation and enables undercollateralized borrows - ([File: contracts/price-aggregator/src/engine.rs](contracts/price-aggregator/src/engine.rs))

### Summary
The price aggregator allows a dual-source oracle to combine a fresh market price with a much older “Fundamental” anchor whenever both observations remain inside their independently configured staleness windows and within the configured price tolerance. [1](#0-0) [2](#0-1)  For volatile assets, that accepted midpoint can materially overvalue collateral after a sharp market move, letting an ordinary `borrow` withdraw debt that fresh prices would reject. [3](#0-2) [4](#0-3) 

### Finding Description
`read_source` marks an observation stale only when either its source-specific `max_stale_seconds` or the oracle-wide `max_price_stale_seconds` is exceeded. [2](#0-1)  `blend` then rejects two readings only if a leg is stale, if both legs have `FeedNature::Market` and differ by more than `MAX_LEG_AGE_SPREAD_SECONDS`, or if their prices are outside the configured tolerance; otherwise it uses the arithmetic midpoint. [1](#0-0)  Because the age-spread check is conditional on both legs being `Market`, a `Fundamental` anchor can lag the market leg by far more than one hour without triggering staleness. [1](#0-0) [5](#0-4) 

This is reachable in the mainnet XLM configuration: its Reflector TWAP leg has a 1-hour source window, while its RedStone `Fundamental` leg has a 46,800-second window, with a 10% upper deviation ratio. [6](#0-5)  The controller fetches aggregator prices into the invocation context, and collateral valuation directly consumes `cached_price` when computing LTV-weighted collateral and health totals. [7](#0-6) [8](#0-7) 

The existing harness demonstrates the exact issue with a frozen $1.00 anchor, a fresh $0.91 primary, a 23-hour-old anchor inside an 86,400-second window, and a 1,000-bps tolerance. [9](#0-8) [10](#0-9)  Under that accepted blend, the account’s collateral is inflated by more than 4%, a 70,000-USDC borrow succeeds, and the fresh-anchor control rejects the same borrow with `INSUFFICIENT_COLLATERAL`. [4](#0-3) 

### Impact Explanation
An attacker can supply the volatile collateral, wait for a real market decline while the slower anchor still reports an older higher price, and call `borrow` to extract more debt assets than the fresh collateral value supports. [3](#0-2) [11](#0-10)  Because valuation uses the midpoint rather than the fresh market leg, the attacker can leave an undercollateralized position, causing lender loss and potentially protocol insolvency when the position is later liquidated or written down. [8](#0-7) [12](#0-11) 

### Likelihood Explanation
The attack does not require compromising either oracle or violating the configured tolerance: the stale provider only has to remain inside its configured age window while the fresh provider reflects a sufficiently sharp move. [2](#0-1) [13](#0-12)  The required divergence is bounded by the configured 10% tolerance, which is within the range of volatility for assets such as XLM, while the mainnet configuration permits the Fundamental anchor to be up to 13 hours old. [6](#0-5)  Any unprivileged borrower can reach the vulnerable path through `borrow`, `withdraw`, `flash_position`, or `multiply` when those flows load the affected collateral and debt prices. [14](#0-13) [15](#0-14) 

### Recommendation
For volatile dual-source oracles, require freshness and timestamp proximity across all source natures rather than applying `MAX_LEG_AGE_SPREAD_SECONDS` only when both legs are `Market`. [1](#0-0)  Set the slower leg’s `max_stale_seconds` close to the primary market leg’s update cadence, or derive the accepted price from the freshest leg when the legs differ materially in observation age while still checking both legs for deviation. [6](#0-5)  At minimum, reduce volatile assets’ Fundamental windows from the current 46,800-second shape to a market-appropriate window and add regression coverage that rejects a lagging anchor capable of moving the midpoint enough to alter a solvency decision. [4](#0-3) 

### Proof of Concept
The repository already contains a working regression-style PoC in `tests/test-harness/tests/controller/audit_borrow_withdraw_liquidate_stale_anchor_blend.rs`. [16](#0-15)  It configures XLM with a fresh Reflector primary and a RedStone anchor whose observation is 82,800 seconds old but still inside its configured 86,400-second staleness budget. [9](#0-8) [10](#0-9) 

The stale anchor remains at $1.00 while the fresh market source moves to $0.91; because the ratio is within the configured 10% band, the aggregator accepts and blends the two values. [1](#0-0) [9](#0-8)  After Alice supplies 100,000 XLM, `try_borrow` for 70,000 USDC succeeds in the stale-anchor run while the otherwise identical fresh-anchor run fails with `INSUFFICIENT_COLLATERAL`. [17](#0-16) [4](#0-3)  The measured valuation inflation is greater than 4%, directly converting the stale blend into excess borrowing capacity. [18](#0-17)

### Citations

**File:** contracts/price-aggregator/src/engine.rs (L419-430)
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
```

**File:** contracts/price-aggregator/src/engine.rs (L542-560)
```rust
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

**File:** interfaces/controller/src/lib.rs (L23-37)
```rust
    fn borrow(
        env: Env,
        caller: Address,
        account_id: u64,
        borrows: Vec<(HubAssetKey, i128)>,
        to: Option<Address>,
    );

    fn withdraw(
        env: Env,
        caller: Address,
        account_id: u64,
        withdrawals: Vec<(HubAssetKey, i128)>,
        to: Option<Address>,
    ) -> Vec<(HubAssetKey, i128)>;
```

**File:** interfaces/controller/src/lib.rs (L60-86)
```rust
    fn flash_position(
        env: Env,
        caller: Address,
        account_id: u64,
        spoke_id: u32,
        mode: PositionMode,
        debt: HubAssetKey,
        amount: i128,
        receiver: Address,
        data: Bytes,
        collaterals: Vec<(HubAssetKey, i128)>,
        refund_assets: Vec<Address>,
    ) -> u64;

    fn multiply(
        env: Env,
        caller: Address,
        account_id: u64,
        spoke_id: u32,
        collateral: HubAssetKey,
        debt_to_flash_loan: i128,
        debt: HubAssetKey,
        mode: PositionMode,
        swap: Bytes,
        initial_payment: Option<(HubAssetKey, i128)>,
        convert_swap: Option<Bytes>,
    ) -> u64;
```

**File:** tests/test-harness/tests/controller/audit_borrow_withdraw_liquidate_stale_anchor_blend.rs (L1-18)
```rust
use test_harness::mock_redstone::MockRedStonePriceFeedClient;
use test_harness::oracle::redstone::register_redstone_adapter;
use test_harness::{assert_contract_error, errors, usd, usd_cents, LendingTest, ALICE, BOB};

const ANCHOR_FROZEN_PRICE: i128 = usd(1);
const TRUE_FRESH_PRICE: i128 = usd_cents(91);
const XLM_TOLERANCE_BPS: u32 = 1000;
const ANCHOR_MAX_STALE_SECONDS: u64 = 86_400;
const ANCHOR_LAG_SECONDS: u64 = 82_800;

const XLM_SUPPLY: f64 = 100_000.0;

const TARGET_BORROW: f64 = 70_000.0;

struct Outcome {
    collateral_usd: f64,
    borrow: Result<(), soroban_sdk::Error>,
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

**File:** tests/test-harness/tests/controller/audit_borrow_withdraw_liquidate_stale_anchor_blend.rs (L57-67)
```rust
    t.supply(BOB, "USDC", 500_000.0);

    t.supply(ALICE, "XLM", XLM_SUPPLY);

    let collateral_usd = t.total_collateral(ALICE);
    let borrow = t.try_borrow(ALICE, "USDC", TARGET_BORROW);

    Outcome {
        collateral_usd,
        borrow,
    }
```

**File:** tests/test-harness/tests/controller/audit_borrow_withdraw_liquidate_stale_anchor_blend.rs (L71-93)
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
```

**File:** common/src/oracle/observation.rs (L30-34)
```rust
/// Largest timestamp gap between two market-nature legs of a blended price
/// before the blend is marked stale.
///
/// A TWAP leg carries the timestamp of the oldest sample in its window.
pub const MAX_LEG_AGE_SPREAD_SECONDS: u64 = 3_600;
```

**File:** configs/mainnet/markets.json (L61-97)
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

**File:** contracts/controller/src/risk/totals.rs (L81-97)
```rust
    cache.load_markets(&supply_positions.keys());

    let mut ltv = Wad::ZERO;
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
