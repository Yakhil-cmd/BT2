### Title
Planted dust collateral leg with an attacker-controllable Aquarius LP price permanently blocks liquidation and bad-debt cleanup - (File: contracts/price-aggregator/src/providers/aquarius.rs)

### Summary
`supply` admits a new collateral leg without requiring a usable price for it, while `liquidate` and `clean_bad_debt` both call `calculate_account_risk_totals`, which needs a strict price for **every** supply position on the account. For a collateral asset priced as an Aquarius LP share, `read` fails with `InsufficientAquariusLiquidity` whenever the pool's total value falls below `lp.min_pool_value_wad` — a condition any unprivileged LP can trigger at will by withdrawing their own liquidity. A borrower can therefore plant a dust LP collateral leg, drain the Aquarius pool below the floor with their own withdrawal, and make their underwater account unliquidatable and un-cleanable for as long as they keep the pool depleted — mirroring CVE-2022-21599's class (an attacker-reachable condition that makes a core operation hang/fail repeatedly).

### Finding Description
- `supply` only enforces `require_can_supply` (listed, unhalted, `is_collateralizable`); it performs no price read, so a leg in an unpriceable asset is accepted — confirmed by `tests/test-harness/tests/controller/audit_supply_stale_shield.rs` where `supply` succeeds while the feed is stale. [1](#0-0) [2](#0-1) 
- `build_liquidation_plan` and `socialize_bad_debt` both invoke `risk::calculate_account_risk_totals` over all supply positions; one unpriceable leg aborts the whole call. [3](#0-2) [4](#0-3) 
- In the Aquarius provider, `pool_value_wad < lp.min_pool_value_wad` returns `Err(InsufficientAquariusLiquidity)` — pool value is `price_wad * total_shares / share_unit`, which shrinks directly as LPs withdraw reserves/shares. [5](#0-4) 
- `withdraw` of the poisoned leg also fails while the leg is unpriceable if the account retains debt (`require_post_pool_risk_gates` reads all leg prices), so the borrower cannot even accidentally remove it via the normal path — and doesn't need to. [6](#0-5) 
- The threat model documents the primitive (DoS.1) but no gate prevents planting or refreshing the leg; `update_account_threshold` also reads all leg prices in `has_risks` mode. [7](#0-6) 

### Impact Explanation
While the Aquarius pool stays below `min_pool_value_wad`, every `liquidate` and `clean_bad_debt` call against the account reverts. Interest keeps accruing on the unbacked debt, liquidation bonus elapses unclaimed, and the bad debt cannot be socialized — forcing eventual supply-index write-downs borne by honest suppliers (temporary freezing of liquidation on the account plus protocol insolvency cost). The attacker fully controls duration: re-add LP liquidity to lift the price, withdraw again to re-arm. Cost is one dust LP leg plus their own liquidity.

### Likelihood Explanation
Reachable by a single unprivileged address: `supply(caller, account_id, spoke_id, [(lp_hub_asset, dust)])`, then a standard Aquarius `withdraw_liquidity` on their own pool position — both explicitly in-scope. No privileged flags, no oracle dishonesty, no timing race. The same shape works via feed staleness (any listed asset whose feed the borrower expects to go stale), broadening applicability beyond LP collaterals.

### Recommendation
- Exclude supply legs that cannot be strictly priced from collateralization at `supply` time (reject the supply when the leg's price is unavailable, or mark the leg non-collateral until priced).
- Alternatively, treat an unpriceable dust-valued leg as zero-value (with a conservative cap) inside `calculate_account_risk_totals` for the liquidation path, so one bad leg cannot veto the whole account.
- For Aquarius-sourced assets, consider making `min_pool_value_wad` failure degrade to a zero/haircut valuation rather than a hard error, or require a minimum absolute collateral value for LP-token legs.

### Proof of Concept
Modeled on `audit_supply_stale_shield.rs` / `audit_liquidate_and_clean_bricked_by_unpriceable_dust_leg.rs`, with the Aquarius trigger:

1. Attacker supplies real collateral and borrows to near the limit: `supply(E, acct, spoke, [(USDC, 10_000)])`, `borrow(E, acct, [(ETH, 3.0)])`.
2. Attacker supplies a dust leg of `LP_AQ` (an Aquarius-LP-priced collateral asset) in a pool where the attacker holds ≥ enough share to push `price_wad * total_shares / share_unit < min_pool_value_wad`: `supply(E, acct, spoke, [(LP_AQ, dust)])` — succeeds, no price read.
3. Attacker calls the Aquarius pool's `withdraw_liquidity` for their own shares → subsequent aggregator reads return `InsufficientAquariusLiquidity`.
4. Price move pushes `HF < 1`. Any `liquidate(liquidator, acct, [(ETH, x)], Transfer)` reverts inside `calculate_account_risk_totals`; `clean_bad_debt(caller, acct)` reverts identically even after the account is insolvent.
5. Debt keeps accruing at the borrow index while untouchable; when eventually socialized (via `force_socialize_bad_debt` after liquidity returns), suppliers absorb a larger index write-down than if liquidation had executed on time.

### Citations

**File:** contracts/controller/src/positions/mod.rs (L216-228)
```rust
pub(crate) fn require_can_supply(
    env: &Env,
    cache: &mut Context,
    spoke_id: u32,
    hub_asset: &HubAssetKey,
) {
    let asset_config = require_listed_unhalted_config(env, cache, spoke_id, hub_asset);
    assert_with_error!(
        env,
        asset_config.is_collateralizable,
        CollateralError::NotCollateral
    );
}
```

**File:** tests/test-harness/tests/controller/audit_supply_stale_shield.rs (L26-31)
```rust
    let plant = t.try_supply(ALICE, "WBTC", 0.001);
    assert!(
        plant.is_ok(),
        "supply must accept the leg even though WBTC's feed is stale: {plant:?}"
    );
    t.assert_position_exists(ALICE, "WBTC", PositionType::Supply);
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

**File:** contracts/controller/src/positions/liquidation/mod.rs (L222-235)
```rust
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
```

**File:** contracts/price-aggregator/src/providers/aquarius.rs (L115-122)
```rust
    let share_unit = 10i128
        .checked_pow(share_decimals)
        .ok_or(OracleError::InvalidPrice)?;
    let pool_value_wad = try_mul_div_half_up(&env, price_wad, total_shares, share_unit)
        .ok_or(OracleError::InvalidPrice)?;
    if pool_value_wad < lp.min_pool_value_wad {
        return Err(OracleError::InsufficientAquariusLiquidity);
    }
```

**File:** contracts/controller/src/risk/validation.rs (L29-45)
```rust
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
```

**File:** docs/explanation/threat-model.md (L364-365)
```markdown
| DoS.1 | Price outage blocks valuation-dependent actions, including liquidation; fail-closed availability cost. Supply needs no price, so an indebted borrower can add a dust leg of any listed collateral and choose which feed outage shields the account. For an Aquarius LP leg, liquidity providers can cause that outage by withdrawing pool value below `min_pool_value_wad`. The same leg blocks bad-debt cleanup and force-socialization. |
| DoS.2 | Selected paused debt or no_seize collateral blocks liquidation; distinct flag policies matter. |
```
