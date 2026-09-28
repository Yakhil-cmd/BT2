### Title
Unprivileged borrower can shield an underwater account from liquidation and bad-debt cleanup by holding an Aquarius LP collateral leg whose pool they can drain below `min_pool_value_wad` - (File: contracts/price-aggregator/src/providers/aquarius.rs)

### Summary
Collateral pricing fails closed for the entire account: if any one supply leg cannot be priced, `liquidate`, `clean_bad_debt`, and `force_socialize_bad_debt` all revert. Aquarius LP shares are priced from live pool reserves, and `aquarius::read` returns `OracleError::InsufficientAquariusLiquidity` whenever the pool's computed WAD value falls below the configured `min_pool_value_wad` (1e24 ≈ $1M on every listed mainnet LP market). A borrower who is also a liquidity provider in the Aquarius pool backing a listed LP collateral can supply a dust LP leg to their own account and then withdraw their own liquidity, driving pool value under the floor. Every subsequent liquidation and cleanup call on that account reverts until the attacker re-adds liquidity, letting debt accrue into deep insolvency that is ultimately socialized onto suppliers.

### Finding Description
`providers::aquarius::read` computes `pool_value_wad = price_wad * total_shares / 10^share_decimals` and rejects the observation when `pool_value_wad < lp.min_pool_value_wad` (`InsufficientAquariusLiquidity`) [1](#0-0) . The LP price is derived from `aquarius_pool_reserves_call` / `aquarius_total_shares_call`, i.e. live pool state that any LP can change by withdrawing [2](#0-1) . All listed LP collaterals on mainnet (XLMUSDC_LP, USDYUSDC_LP, XLMAQUA_LP, etc.) use this single source with `min_pool_value_wad = 1_000_000e18` [3](#0-2) .

On the controller side, `supply` accepts a leg without requiring its price to be resolvable, and account risk valuation reads every collateral leg's price, so one unpriceable leg aborts the whole health-factor computation. The harness tests prove the failure shape: a dust leg whose feed is unpriceable makes `liquidate` and `clean_bad_debt` revert while the debt remains [4](#0-3) , and the threat model explicitly names this scenario — "For an Aquarius LP leg, liquidity providers can cause that outage by withdrawing pool value below `min_pool_value_wad`. The same leg blocks bad-debt cleanup and force-socialization" [5](#0-4) .

The attacker-reachable path uses only permitted entrypoints: `supply` (own account, dust amount of the LP token), `borrow` against it, then a liquidity withdrawal on the Aquarius pool the attacker already provides to — an "own trade on Aquarius". No privileged role, leaked key, or third-party oracle dishonesty is involved; the manipulation target is live pool reserves, not a feed within bands.

### Impact Explanation
Temporary freezing of funds escalating to protocol insolvency. While the pool sits below the floor: (1) no liquidator can repay or seize any of the account's collateral — every offer reverts during risk-total pricing; (2) `clean_bad_debt` and the owner-gated `force_socialize_bad_debt` revert, so the dust socialization path cannot clear the account either; (3) interest keeps accruing on the debt (accrual does not need prices). The attacker can keep the pool drained indefinitely at the cost of holding their liquidity outside the pool, then restore it and re-drain it at will to dodge individual liquidation attempts. Each day of shielding deepens the shortfall that is eventually written down against the supply index and borne by suppliers — a direct, attacker-controlled conversion of a liquidatable position into socialized bad debt.

### Likelihood Explanation
Requires the attacker to control enough LP share in a listed-collateral Aquarius pool to pull its total value under $1M — feasible for the dominant LP in a thin pool, or by coordinating withdrawals in a pool near the floor. It costs locked capital, not burned capital, and no exploit primitive beyond public entrypoints. The shield is per-account and self-applied, so it only protects the attacker's own bad debt, which bounds the blast radius to the debt they can open. Medium.

### Recommendation
Do not let a single unpriceable collateral leg fail closed over the whole account. Options: value a `InsufficientAquariusLiquidity` leg at zero (treat the leg as absent for HF while keeping seizure of it optional) so liquidation can proceed on the remaining legs; or add a liquidation path that skips legs whose only failure is a missing price, seizing the priceable collateral and leaving the poisoned leg; or make `clean_bad_debt`/`force_socialize_bad_debt` tolerate unpriceable supply legs by sweeping them to revenue at zero value. Independently, consider gating `supply` on a successfully resolvable price for collateral-enabled assets so an already-unpriceable leg cannot be planted.

### Proof of Concept
1. Attacker is a large LP in Aquarius pool `CA6PUJ...` (XLM/USDC) whose share token `CAVKLY...` is listed collateral `XLMUSDC_LP` with `min_pool_value_wad = 1e24`.
2. `controller.supply(attacker, account_id, spoke, [(XLMUSDC_LP, dust)])` — succeeds; supply does not resolve the leg's price (same acceptance as the stale-feed plant in `audit_supply_stale_shield.rs` lines 26–30).
3. `controller.supply` + `controller.borrow` on other listed assets to open maximum debt against the account.
4. Market moves (or attacker waits for accrual) until `HF < 1`; verify `can_be_liquidated`.
5. Attacker calls `withdraw` on the Aquarius pool, pulling reserves until `price_wad * total_shares / 1e7 < 1e24`. `aquarius::read` now returns `InsufficientAquariusLiquidity` (aquarius.rs:120–122), the same code path proven by `test_lp_read_rejects_liquidity_below_floor` [6](#0-5) .
6. `controller.liquidate(liquidator, attacker_id, payments, ...)` → reverts during collateral valuation, mirroring the `PRICE_FEED_STALE` bricking shown in `audit_liquidate_and_clean_stale_leg.rs` lines 36–40; `controller.clean_bad_debt(attacker_id)` → same revert; `force_socialize_bad_debt` likewise fails, per threat-model DoS.1.
7. Debt accrues unpaid while every remediation path is bricked; when the attacker eventually lets liquidation through (or governance force-socializes after the pool refills), the accrued shortfall above collateral is written down against the supply index — loss borne by suppliers.

### Citations

**File:** contracts/price-aggregator/src/providers/aquarius.rs (L90-93)
```rust
    let (reserve_a, reserve_b) =
        aquarius_pool_reserves_call(&env, &lp.pool).ok_or(OracleError::NoLastPrice)?;
    let total_shares =
        aquarius_total_shares_call(&env, &lp.pool).ok_or(OracleError::NoLastPrice)?;
```

**File:** contracts/price-aggregator/src/providers/aquarius.rs (L118-122)
```rust
    let pool_value_wad = try_mul_div_half_up(&env, price_wad, total_shares, share_unit)
        .ok_or(OracleError::InvalidPrice)?;
    if pool_value_wad < lp.min_pool_value_wad {
        return Err(OracleError::InsufficientAquariusLiquidity);
    }
```

**File:** configs/mainnet/markets.json (L1207-1220)
```json
            "AquariusLp": {
              "pool": "CA6PUJLBYKZKUEKLZJMKBZLEKP2OTHANDEOWSFF44FTSYLKQPIICCJBE",
              "token_a": "CAS3J7GYLGXMF6TDJBBYYSE3HQ6BBSMLNUQ34T6TZMYMW2EVH34XOWMA",
              "token_b": "CCW67TSZV3SSS2HXMBQ5JFGCKJNXKZM7UQUWUZPUTHXSTZLEO7SJMI75",
              "key_a": {
                "Token": "CAS3J7GYLGXMF6TDJBBYYSE3HQ6BBSMLNUQ34T6TZMYMW2EVH34XOWMA"
              },
              "key_b": {
                "Token": "CCW67TSZV3SSS2HXMBQ5JFGCKJNXKZM7UQUWUZPUTHXSTZLEO7SJMI75"
              },
              "reserve_a_decimals": 7,
              "reserve_b_decimals": 7,
              "min_pool_value_wad": "1000000000000000000000000"
            }
```

**File:** tests/test-harness/tests/controller/audit_liquidate_and_clean_stale_leg.rs (L26-41)
```rust
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

```

**File:** docs/explanation/threat-model.md (L364-364)
```markdown
| DoS.1 | Price outage blocks valuation-dependent actions, including liquidation; fail-closed availability cost. Supply needs no price, so an indebted borrower can add a dust leg of any listed collateral and choose which feed outage shields the account. For an Aquarius LP leg, liquidity providers can cause that outage by withdrawing pool value below `min_pool_value_wad`. The same leg blocks bad-debt cleanup and force-socialization. |
```

**File:** contracts/price-aggregator/tests/oracle/registry.rs (L744-763)
```rust
fn test_lp_read_rejects_liquidity_below_floor() {
    let env = Env::default();
    env.ledger().set_timestamp(1_000_000);
    with_contract(&env, || {
        let (pool, share, mut oracle) = listable_lp(
            &env,
            "standard",
            10_000_000_000,
            10_000_000_000,
            10_000_000_000,
        );
        set_lp_min_pool_value(&mut oracle, 1_000 * WAD);
        let key = PriceKey::Token(share);
        set_oracle(&env, key.clone(), oracle);
        crate::test_support::MockAquariusPoolClient::new(&env, &pool)
            .set_reserves(&100_000_000, &100_000_000);

        let mut session = Session::new(&env);
        assert!(!crate::engine::resolve_status(&mut session, &key, 0).valid);
    });
```
