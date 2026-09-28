### Title
A single stale or unavailable price for any account collateral or debt leg freezes both `liquidate` and `clean_bad_debt` - (File: contracts/controller/src/positions/liquidation/plan.rs)

### Summary
`liquidate` and `clean_bad_debt` value every supply and debt position on the target account before checking whether the account is liquidatable or socializable. Because the price aggregator’s strict `prices` path aborts on any stale, missing, non-positive, deviating, or sanity-band-violating source, one unusable asset anywhere in the portfolio makes the entire liquidation or cleanup transaction revert. A borrower can therefore carry a tiny collateral leg in an asset with a fragile oracle and become temporarily immune to liquidation when that feed goes stale, even if the debt and economically relevant collateral remain perfectly priceable.

### Finding Description
`Controller::liquidate` is permissionless and calls `process_liquidation` [1](#0-0) . `process_liquidation` calls `build_liquidation_plan` before transferring repayment [2](#0-1) . The plan calls `calculate_account_risk_totals` over the account’s complete `supply_positions` and `borrow_positions`, not just the submitted debt payment and profitable collateral legs [3](#0-2) .

`calculate_account_risk_totals_body` calls `Context::load_markets` for the concatenated supply and debt hub keys [4](#0-3) . `load_markets` converts every hub key into a token address and calls `fetch_prices` for all of them [5](#0-4) . `fetch_prices` invokes the price aggregator’s `prices` endpoint and panics if any requested token lacks a returned feed [6](#0-5) .

The aggregator’s `prices` endpoint resolves every requested key through `engine::resolve` [7](#0-6) . `force` panics for any unusable outcome [8](#0-7) ; `Outcome::failure` marks stale, deviating, non-positive, missing, and out-of-band prices unusable [9](#0-8) . Consequently, one failed oracle aborts valuation of the entire account before the health-factor check can complete.

The same root cause affects the permissionless `clean_bad_debt` path. `process_clean_bad_debt` calls `socialize_bad_debt`, which computes the same account-wide risk totals before it tests the dust-capped bad-debt admission predicate [10](#0-9) . Thus even the fallback that should socialize an insolvent account can revert on the unrelated bad price.

The repository already contains a reproduction: `audit_liquidate_and_clean_bricked_by_unpriceable_dust_leg` supplies a borrower with USDC collateral and ETH debt, then the borrower adds only `0.001` WBTC after its Reflector price is stale. Both `try_liquidate` and `try_clean_bad_debt_by_id` then fail with `PRICE_FEED_STALE`; refreshing WBTC makes the identical liquidation succeed [11](#0-10) .

### Impact Explanation
An unhealthy account can remain immune to liquidation during an oracle outage or asset collapse, precisely when timely liquidation is most important. If the collateral’s real market value continues falling while transactions revert, the account can become deeply insolvent, removing the liquidation incentive and leaving suppliers or the protocol to absorb losses. Because `clean_bad_debt` also performs full valuation, the permissionless emergency cleanup path can be unavailable for the same reason. This can produce temporary freezing of liquidation and, if the outage persists or prices continue deteriorating, protocol insolvency.

### Likelihood Explanation
No privileged action is required to create the fragile position: an ordinary borrower can supply a listed asset as collateral before borrowing other assets. The issue then triggers whenever that asset’s configured feed cannot produce a strict price, including stale provider data, a missing read, a zero/nonpositive price, source disagreement, or a sanity-band rejection. The included test uses only ordinary account operations plus a stale mock Reflector observation to demonstrate the exact failure. The outage itself is external, but the protocol’s account-wide, fail-closed valuation is what turns one dust leg into an account-wide liquidation block.

### Recommendation
Avoid requiring every collateral leg to be priceable before liquidation eligibility is determined. At minimum:

- Exclude zero-value or economically negligible collateral legs from the initial liquidation eligibility check, with conservative dust bounds.
- Allow liquidation plans to select only priceable collateral legs and value those legs independently.
- Let `clean_bad_debt` proceed when debt is priceable but collateral valuation fails, treating unpriceable collateral as zero for admission while still seizing only positions that can be safely valued.
- Add an explicit emergency path that preserves healthy-price debt repayment and rejects seizure of unpriceable collateral instead of aborting the whole transaction.
- Keep strict price validation for every asset actually repaid or seized.

### Proof of Concept
1. `LIQUIDATOR` supplies enough USDC to the pool.
2. `ALICE` supplies `10,000 USDC` and borrows `3 ETH`.
3. `ALICE` supplies a dust amount such as `0.001 WBTC`, creating an extra collateral leg.
4. WBTC’s provider observation becomes older than its configured `max_stale_seconds`.
5. USDC falls to `$0.50`, making `ALICE` economically liquidatable.
6. Any liquidator calls `Controller::liquidate(liquidator, alice_account_id, [(ETH_hub_key, 1 ETH)], SeizeMode::Transfer)`.
7. `build_liquidation_plan` calls `calculate_account_risk_totals`, which loads prices for USDC, ETH, and WBTC. The WBTC strict resolution panics with `OracleError::PriceFeedStale`, so the liquidation reverts.
8. A permissionless caller invokes `clean_bad_debt(caller, alice_account_id)`. It reaches the same account-wide risk calculation and also reverts with `PriceFeedStale`.
9. After WBTC receives a fresh price, the identical liquidation succeeds, confirming that the only blocker was the unrelated stale collateral leg.

### Citations

**File:** contracts/controller/src/lib.rs (L144-158)
```rust
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

**File:** contracts/controller/src/positions/liquidation/mod.rs (L46-58)
```rust
    let mut account = storage::get_account(env, account_id);

    let mut cache = Context::new(env);

    require_non_empty_payments(env, debt_payments);

    // Reject an unusable receiver before moving tokens.
    let mut receiver = resolve_seize_receiver(
        env, liquidator, account_id, &account, seize_mode, &mut cache,
    );

    // Share payment normalization and positivity checks with the estimate view.
    let liquidation_plan = plan::build_liquidation_plan(env, &account, debt_payments, &mut cache);
```

**File:** contracts/controller/src/positions/liquidation/mod.rs (L195-237)
```rust
/// Authorizes permissionless dust-gated cleanup outside flash loans.
pub(crate) fn process_clean_bad_debt(env: &Env, caller: &Address, account_id: u64) {
    caller.require_auth();
    validation::require_not_flash_loaning(env);
    clean_bad_debt_standalone(env, account_id);
}

/// Admission condition for bad-debt socialization.
#[derive(Clone, Copy, PartialEq)]
enum BadDebtGate {
    /// Permissionless: insolvent *and* collateral at or below the dust threshold.
    DustCapped,
    /// Owner-only: insolvent alone, with no cap on the collateral left behind.
    InsolventOnly,
}

/// Requires open debt and the selected insolvency gate, then cleans up the account.
fn socialize_bad_debt(env: &Env, account_id: u64, gate: BadDebtGate) {
    let mut cache = Context::new(env);
    let account = storage::get_account(env, account_id);

    assert_with_error!(
        env,
        !account.borrow_positions.is_empty(),
        CollateralError::DebtPositionNotFound
    );

    let totals = risk::calculate_account_risk_totals(
        env,
        &mut cache,
        &account.supply_positions,
        &account.borrow_positions,
    );

    let admits = match gate {
        BadDebtGate::DustCapped => {
            is_socializable_bad_debt(totals.total_debt, totals.total_collateral)
        }
        BadDebtGate::InsolventOnly => totals.total_debt > totals.total_collateral,
    };
    assert_with_error!(env, admits, CollateralError::CannotCleanBadDebt);

    bad_debt::execute_bad_debt_cleanup(env, &mut cache, account_id, &account, &totals);
```

**File:** contracts/controller/src/positions/liquidation/plan.rs (L34-44)
```rust
    let totals = risk::calculate_account_risk_totals(
        env,
        cache,
        &account.supply_positions,
        &account.borrow_positions,
    );
    assert_with_error!(
        env,
        totals.health_factor < Wad::ONE,
        CollateralError::HealthFactorTooHigh
    );
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

**File:** contracts/controller/src/context.rs (L68-74)
```rust
    /// Loads missing prices by token address and missing indexes by hub-asset key.
    /// Already cached values are retained.
    pub(crate) fn load_markets(&mut self, hub_assets: &Vec<HubAssetKey>) {
        let assets = unique_hub_tokens(&self.env, hub_assets);
        self.fetch_prices(&assets);
        self.fetch_market_indexes(hub_assets);
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

**File:** contracts/price-aggregator/src/engine.rs (L122-147)
```rust
    /// Returns the error that makes this outcome unusable against `oracle`, if
    /// any. Checks, in order: an error already carried on the outcome, a missing
    /// oracle, staleness, deviation, a non-positive price, and the oracle's
    /// sanity price bounds. Returns `None` when none of these apply.
    fn failure(&self, oracle: Option<&AssetOracle>) -> Option<OracleError> {
        if let Some(err) = self.err {
            return Some(err);
        }
        let Some(oracle) = oracle else {
            return Some(OracleError::OracleNotConfigured);
        };
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
        }
        None
```

**File:** contracts/price-aggregator/src/engine.rs (L178-188)
```rust
/// Converts `outcome` into a `PriceFeedRaw`, panicking with the applicable
/// `OracleError` if the outcome is unusable against `oracle` or `oracle` is
/// `None`.
pub(crate) fn force(env: &Env, outcome: &Outcome, oracle: Option<&AssetOracle>) -> PriceFeedRaw {
    if let Some(err) = outcome.failure(oracle) {
        panic_with_error!(env, err);
    }
    let Some(oracle) = oracle else {
        panic_with_error!(env, OracleError::OracleNotConfigured)
    };
    outcome.to_feed(oracle.asset_decimals)
```

**File:** tests/test-harness/tests/controller/audit_liquidate_and_clean_stale_leg.rs (L20-47)
```rust
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
