### Title
Attacker-planted dust collateral leg with a fail-closed price feed bricks liquidation and bad-debt cleanup of the attacker's own insolvent account — (File: contracts/controller/src/risk/validation.rs)

### Summary
The advisory class is "untrusted input reaches an unchecked error path that aborts the whole operation." On XOXNO Lending the analog is a collateral leg whose price feed fails closed: `supply` does not require a valid price for the supplied asset, so a borrower can plant a dust leg of an asset whose feed can be made to revert (e.g., an Aquarius LP token whose pool value can be pushed below `min_pool_value_wad`, or a feed allowed to go stale). Every later `liquidate` and `clean_bad_debt` call must strictly price all of the account's legs, so the single failing leg aborts the whole risk/liquidation pipeline — a remote "throw" reachable via the attacker's own crafted account state, permanently shielding bad debt.

### Finding Description
- Supply-side gating checks position structure and spoke flags, but never requires the supplied asset's price to be fresh or valid: `validate_position_entry_gates` only calls `validate_bulk_position_limits`, `require_whole_unit_isolation` (decimals check only), and `require_can_supply` [1](#0-0) . `require_whole_unit_isolation` only reads `params.asset_decimals`, never the price [2](#0-1) .
- Liquidation prices every leg through the strict price cache: `whole_unit_repayment` and the HF/plan path call `cache.cached_price(&hub_asset.asset)`, which panics (e.g., `PriceFeedStale`) when the feed is invalid [3](#0-2) .
- The harness confirms the exploit end-to-end: `try_supply` of a 0.001 WBTC leg succeeds while the WBTC feed is stale, after which both `try_liquidate` and `try_clean_bad_debt_by_id` revert with `PRICE_FEED_STALE` [4](#0-3) .
- Permanence: for an Aquarius LP collateral leg, the attacker (or any LP) can withdraw pool liquidity below `min_pool_value_wad`, so the fair-value read fails indefinitely rather than merely going stale — the threat model itself notes the LP leg lets liquidity providers cause the outage and that the same leg blocks bad-debt cleanup and force-socialization [5](#0-4) .

### Impact Explanation
The attacker borrows real assets, then plants/renders-unpriceable the dust leg. The account can never be liquidated and never cleaned up via `clean_bad_debt` (and forced socialization is likewise blocked), converting a recoverable loss into permanent protocol insolvency and freezing the underlying suppliers' backing — satisfying "permanent freezing of funds / protocol insolvency."

### Likelihood Explanation
Fully permissionless: `supply` (dust leg) and Aquarius LP `withdraw` are unprivileged operations any address can perform; cost is one dust deposit plus the attacker's own borrow position. Requires only a listed collateral whose feed can be made invalid (LP-below-floor or stale feed), which the listing set can plausibly contain.

### Recommendation
Require a valid strict price (or a minimum USD floor) for any newly opened supply slot, not just decimals; alternatively, let liquidation/cleanup skip or haircut-to-zero legs whose price read fails instead of aborting the entire plan, and exclude unpriceable legs from the liquidation-blocking path while still seizing the priceable remainder.

### Proof of Concept
See `audit_liquidate_and_clean_bricked_by_unpriceable_dust_leg`: supply 10,000 USDC, borrow 3 ETH, plant 0.001 WBTC while its feed is stale, drop USDC 50% — `liquidate` and `clean_bad_debt` both revert with `PRICE_FEED_STALE` [6](#0-5) . For the permanent variant, use an Aquarius LP token leg and withdraw pool value below `min_pool_value_wad` so the feed never recovers.

### Citations

**File:** contracts/controller/src/positions/mod.rs (L231-252)
```rust
pub(crate) fn validate_position_entry_gates(
    env: &Env,
    account: &Account,
    aggregated: &AggregatedPayments,
    cache: &mut Context,
    position_type: AccountPositionType,
) {
    validation::validate_bulk_position_limits(env, account, position_type, aggregated);
    if matches!(position_type, AccountPositionType::Deposit) {
        validation::require_whole_unit_isolation(env, cache, account, aggregated);
    }

    for (hub_asset, _) in aggregated {
        match position_type {
            AccountPositionType::Deposit => {
                require_can_supply(env, cache, account.spoke_id, &hub_asset);
            }
            AccountPositionType::Borrow => {
                require_can_borrow(env, cache, account.spoke_id, &hub_asset);
            }
        }
    }
```

**File:** contracts/controller/src/risk/validation.rs (L137-147)
```rust
    for hub_asset in checked.iter() {
        let decimals = cache
            .cached_pool_sync_data(&hub_asset)
            .params
            .asset_decimals;
        assert_with_error!(
            env,
            decimals >= MIN_BORROWABLE_ASSET_DECIMALS,
            CollateralError::PositionLimitExceeded
        );
    }
```

**File:** contracts/controller/src/positions/liquidation/math.rs (L249-257)
```rust
    let feed = cache.cached_price(&hub_asset.asset);
    if feed.asset_decimals >= MIN_BORROWABLE_ASSET_DECIMALS {
        return quote_usd;
    }
    let supply_index = cache.cached_market_index(&hub_asset).supply_index;
    let held_units = position
        .scaled_amount
        .mul(env, supply_index)
        .to_asset_floor(env, feed.asset_decimals);
```

**File:** tests/test-harness/tests/controller/audit_liquidate_and_clean_stale_leg.rs (L4-47)
```rust
fn audit_liquidate_and_clean_bricked_by_unpriceable_dust_leg() {
    let mut t = LendingTest::new()
        .three_asset_usdc_eth_wbtc()
        .with_dust_disabled_all_markets()
        .build();

    t.set_oracle_single_spot("WBTC");

    t.supply(LIQUIDATOR, "USDC", 50_000.0);
    let borrower = test_harness::ALICE;
    t.supply(borrower, "USDC", 10_000.0);
    t.borrow(borrower, "ETH", 3.0);

    let fresh = t.try_liquidate(LIQUIDATOR, borrower, "ETH", 1.0);
    test_harness::assert_contract_error(fresh, errors::HEALTH_FACTOR_TOO_HIGH);

    t.advance_time(5_000);
    let now = t.env.ledger().timestamp();
    let wbtc = t.resolve_asset("WBTC");
    t.mock_reflector_client()
        .set_price_at(&wbtc, &usd(60_000), &(now - 3_600));

    let plant = t.try_supply(borrower, "WBTC", 0.001);
    assert!(
        plant.is_ok(),
        "supply must accept the fragile leg with a stale feed: {plant:?}"
    );

    t.set_price("USDC", usd_cents(50));

    let borrower_id = t.resolve_account_id(borrower);

    let liq = t.try_liquidate(LIQUIDATOR, borrower, "ETH", 1.0);
    test_harness::assert_contract_error(liq, errors::PRICE_FEED_STALE);

    let clean = t.try_clean_bad_debt_by_id(borrower_id);
    test_harness::assert_contract_error(clean, errors::PRICE_FEED_STALE);

    t.set_price("WBTC", usd(60_000));
    let recovered = t.try_liquidate(LIQUIDATOR, borrower, "ETH", 1.0);
    assert!(
        recovered.is_ok(),
        "once WBTC is fresh, the identical liquidation must succeed: {recovered:?}"
    );
```

**File:** docs/explanation/threat-model.md (L364-365)
```markdown
| DoS.1 | Price outage blocks valuation-dependent actions, including liquidation; fail-closed availability cost. Supply needs no price, so an indebted borrower can add a dust leg of any listed collateral and choose which feed outage shields the account. For an Aquarius LP leg, liquidity providers can cause that outage by withdrawing pool value below `min_pool_value_wad`. The same leg blocks bad-debt cleanup and force-socialization. |
| DoS.2 | Selected paused debt or no_seize collateral blocks liquidation; distinct flag policies matter. |
```
