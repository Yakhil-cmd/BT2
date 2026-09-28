### Title
Stale secondary "anchor" leg accepted within tolerance lets a borrower mint debt against an outdated blended price — (File: contracts/price-aggregator/src/engine.rs)

### Summary
The NiFi bug class — a hardened primary channel (UI/API pinned to TLS 1.2) alongside a weaker secondary channel (intracluster paths still accepting TLS 1.0/1.1) — maps onto the price aggregator's dual-leg resolution: the primary leg enforces strict freshness, but the secondary "anchor" leg accepts observations up to a much larger `anchor_max_stale_seconds` window. A stale anchor report that still passes its own freshness bound is blended with the fresh primary price within the configured tolerance, producing a midpoint that inflates (or deflates) collateral value. Any unprivileged borrower can call `borrow` while the anchor is lagging and obtain debt beyond true collateral capacity, creating protocol bad debt.

### Finding Description
In the test fixture `audit_borrow_withdraw_liquidate_stale_anchor_blends_5pct_skew_into_ltv`, a dual-source key is configured with a Reflector primary and a RedStone anchor via `reflector_primary_redstone_anchor_config_with_anchor_stale`, with `ANCHOR_MAX_STALE_SECONDS = 86_400` and `XLM_TOLERANCE_BPS = 1000`. The primary Reflector feed is updated to the true fresh price `$0.91`, while the anchor leg is left frozen at `$1.00` with a timestamp `82_800` seconds in the past — inside its own staleness bound, so it is still accepted as a valid leg [1](#0-0) . The two legs agree within the 1000 bps tolerance, so the aggregator returns the floored midpoint (~$0.955), inflating ALICE's XLM collateral by more than 4% relative to the honest fresh-anchor valuation [2](#0-1) . ALICE's `borrow` of `TARGET_BORROW = 70_000` USDC succeeds under the inflated valuation, while the identical borrow under a fresh anchor reverts with `INSUFFICIENT_COLLATERAL` [3](#0-2) . Root cause: staleness/freshness enforcement is asymmetric across legs of a dual-source key — the anchor leg's `max_stale` bound (~1 day) is orders of magnitude weaker than the primary leg's, so agreement-within-tolerance validation (engine `tolerance`/leg checks in `contracts/price-aggregator/src/engine.rs`) still accepts a report that no longer reflects market price. The controller's risk gate then consumes this strict-but-wrong price via `require_post_pool_risk_gates` [4](#0-3) .

### Impact Explanation
An inflated collateral valuation lets a borrower draw more debt than the true NAV supports. When prices normalize (the anchor refreshes or the position is valued at the true price), the account is undercollateralized and the shortfall becomes protocol bad debt socialized onto suppliers via index write-down — protocol insolvency / theft of user funds, since the borrowed assets leave the pool.

### Likelihood Explanation
Reachable by a single unprivileged address: call `borrow` (or `multiply`/`flash_position`) during any window where the anchor feed lags within its configured staleness bound — a routine condition for slow/updating-infrequently feeds, and also inducible if the anchor feed's publisher is delayed. Requires only that the anchor staleness bound is materially larger than realistic price moves scaled by tolerance; the test demonstrates a >4% inflation with default-like parameters. Magnitude is bounded by the leg tolerance (10%), which limits single-key skew, keeping this in the Medium–High range rather than unbounded.

### Recommendation
- Enforce a symmetric freshness bound across all legs of a dual-source key: the effective `max_stale` for every leg should be the minimum of the legs' configured bounds, or a protocol-wide tight cap for risk-relevant reads.
- Alternatively, treat leg timestamps as part of the tolerance check: reject or down-weight a midpoint whose legs' observation times diverge beyond a small skew window.
- Cap `anchor_max_stale_seconds` at admission relative to the configured tolerance so that worst-case drift inside the window cannot exceed `LT`-safety bounds documented in the threat model.

### Proof of Concept
```rust
// tests/test-harness/tests/controller/audit_borrow_withdraw_liquidate_stale_anchor_blend.rs
const ANCHOR_FROZEN_PRICE: i128 = usd(1);        // stale leg
const TRUE_FRESH_PRICE: i128 = usd_cents(91);    // fresh primary leg
const ANCHOR_LAG_SECONDS: u64 = 82_800;          // < max_stale 86_400 → accepted

let cfg = reflector_primary_redstone_anchor_config_with_anchor_stale(
    &env, &reflector, &xlm, &redstone, &feed_id,
    ANCHOR_MAX_STALE_SECONDS, XLM_TOLERANCE_BPS /*1000*/);
t.configure_market_oracle(&xlm, &cfg);
t.set_price("XLM", TRUE_FRESH_PRICE);            // primary now $0.91
redstone_client.set_price_data(&feed_id, &ANCHOR_FROZEN_PRICE,
                               &(now - 82_800) * 1000, ...); // anchor frozen $1.00

t.supply(BOB, "USDC", 500_000.0);
t.supply(ALICE, "XLM", 100_000.0);
let borrow = t.try_borrow(ALICE, "USDC", 70_000.0); // Ok — but control run errors INSUFFICIENT_COLLATERAL
```
The attacker simply calls `borrow` while the anchor leg is stale-but-accepted; the blended midpoint values collateral ~4%+ above the honest valuation and the post-pool risk gates pass on the inflated figure.

### Citations

**File:** tests/test-harness/tests/controller/audit_borrow_withdraw_liquidate_stale_anchor_blend.rs (L30-55)
```rust
    let redstone = register_redstone_adapter(&t, &[("XLM", ANCHOR_FROZEN_PRICE)]);

    t.set_price("XLM", ANCHOR_FROZEN_PRICE);

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

**File:** contracts/controller/src/risk/validation.rs (L27-30)
```rust
/// Requires debt coverage by LTV-weighted collateral, health factor >= 1, and
/// the configured collateral floor. Debt-free accounts skip all three checks.
pub(crate) fn require_post_pool_risk_gates(env: &Env, cache: &mut Context, account: &Account) {
    if account.debt_free() {
```
