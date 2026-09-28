### Title

Stale dual-source oracle leg can inflate collateral and create protocol bad debt - ([File: contracts/price-aggregator/src/engine.rs])

### Summary

A dual-source asset oracle treats a stale-but-not-expired secondary feed as an equivalent pricing leg and blends it with the fresh primary price. The timestamp spread check is skipped unless both legs have `FeedNature::Market`, and `Outcome::stale` is false while the secondary observation remains inside its configured `max_stale_seconds`. An unprivileged borrower can therefore submit `borrow` while a slow secondary feed still carries an old, more favorable price, pass the controller's LTV and health-factor gates, and withdraw debt backed by less real collateral value than the protocol believes exists.

### Finding Description

The bug class from the referenced Unbound report is stale state preserved and consumed after another path has refreshed the current view. Its analog is the aggregator's stale secondary-leg handling.

In `contracts/price-aggregator/src/engine.rs`, `compose` converts two successful source reads into `Legs::Two { primary, anchor }`; `blend` then marks the blended result stale only when either leg is individually stale or when both legs are market feeds and their timestamps differ by more than `MAX_LEG_AGE_SPREAD_SECONDS`. For a fresh primary market feed and an older anchor feed whose nature is not `Market`, the cross-leg spread check is disabled. If the older anchor is still below its own `max_stale_seconds`, the composite result remains usable.

The resulting price is the midpoint:

```rust
let price_wad = midpoint_price_or_zero(anchor.price_wad, primary.price_wad);
```

from `contracts/price-aggregator/src/engine.rs:430`.

The controller then uses that blended `feed.price` to calculate collateral value in `calculate_account_risk_totals_body`, applies the stored LTV and liquidation threshold, and compares debt against those values through `require_post_pool_risk_gates`. A stale anchor that is above the current price therefore shifts the midpoint upward and directly increases `ltv_collateral`, `weighted_collateral`, and `health_factor`.

The repository's exploit regression test demonstrates this with a fresh primary price of `$0.91` and a stale anchor price of `$1.00` that is 82,800 seconds old but still inside an 86,400-second staleness budget. The stale-anchor run values the collateral more than 4% higher and successfully borrows `$70,000`, while the fresh-anchor control reverts with `InsufficientCollateral` in `tests/test-harness/tests/controller/audit_borrow_withdraw_liquidate_stale_anchor_blend.rs:70-93`.

### Impact Explanation

An attacker can supply a volatile collateral asset and call:

```text
borrow(
  caller = attacker,
  account_id = attacker_account,
  borrows = [(HubAssetKey { hub_id, asset: borrow_asset }, amount)],
  to = Some(attacker)
)
```

When the collateral's fresh leg has moved down but the anchor leg remains accepted under `max_stale_seconds`, the midpoint overstates collateral. The controller permits a borrow that would otherwise fail `ltv_collateral >= total_debt` or `health_factor >= 1`.

The attacker receives pool assets immediately through the normal `pool_borrow_call` path. If the true collateral value is insufficient to cover the resulting debt, liquidators cannot restore solvency by seizing the collateral at a normal bonus. Residual debt becomes protocol bad debt and is eventually socialized through the bad-debt mechanism, reducing supplier claims. This is theft of pool funds and can create protocol insolvency rather than a temporary denial of service.

### Likelihood Explanation

Likelihood is conditional on an asset using a dual-source oracle whose secondary source publishes less frequently or is configured with a long staleness allowance. Such configurations are explicitly supported: `MAX_PRICE_STALE_SECONDS` permits up to 93,600 seconds, and `read_source` accepts a leg that has not exceeded `oracle.max_price_stale_seconds`.

No privileged action, leaked key, malicious governance call, or route manipulation is required during exploitation. The attacker needs only an owned account, collateral, and a normal `borrow` call while the anchor feed is naturally or operationally stale. The condition is time-dependent and may not be continuously available, but the demonstrated skew can exceed 4% with a configured 10% tolerance band. Larger stale movement within the configured band produces larger overvaluation.

### Recommendation

Do not blend observations from materially different times when either leg can carry stale economic information. Apply `MAX_LEG_AGE_SPREAD_SECONDS` to every two-source oracle, not only pairs where both sources report `FeedNature::Market`. Alternatively, use the freshest primary value rather than midpointing it with an older anchor, or reject the composite whenever the leg timestamps diverge beyond a conservative bound.

At minimum:

```rust
let stale = primary.stale
    || anchor.stale
    || primary.timestamp.abs_diff(anchor.timestamp) > MAX_LEG_AGE_SPREAD_SECONDS;
```

Long-lived anchor feeds should also have a much shorter cross-check freshness budget than `MAX_PRICE_STALE_SECONDS`, because tolerance-band agreement is meaningful only when both observations describe approximately the same market time.

### Proof of Concept

The existing test `audit_borrow_withdraw_liquidate_stale_anchor_blends_5pct_skew_into_ltv` reproduces the issue:

1. Configure XLM with a fresh Reflector primary and a RedStone secondary.
2. Set the secondary's `max_stale_seconds` to `86_400`.
3. Set the primary XLM price to `$0.91`.
4. Set the secondary observation to `$1.00` with timestamp `now - 82_800` seconds.
5. Supply `100,000 XLM` to the attacker account.
6. Call `borrow` for `$70,000 USDC`.

The stale-anchor run produces a blended price of approximately `$0.955`, inflating collateral by more than 4%, and the borrow succeeds. The control run with both legs at `$0.91` reverts with `InsufficientCollateral`, proving that the stale leg—not account permissions, pool liquidity, or another fixture condition—enabled the unsafe borrow.