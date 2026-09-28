### Title
`liquidate` has no minimum-collateral bound, so a liquidator committing fixed `debt_payments` receives an oracle-priced seizure that can be skewed by a front-running trade on the Aquarius pool feeding the price - (File: contracts/controller/src/lib.rs)

### Summary
The referenced bug class is a price-denominated trade where the caller commits input but cannot bound the oracle-priced output, letting an oracle manipulator front-run the transaction. XOXNO Lending's `liquidate` entrypoint has exactly this shape: the liquidator authorizes a fixed `debt_payments` vector and a `SeizeMode`, but the collateral legs seized are computed at execution time from `Context`-fetched oracle prices and the HF-based bonus curve - there is no `min_collateral` / `max_debt_value` argument. When a collateral (or debt) leg is priced through an Aquarius pool-derived source, an unprivileged attacker can move the on-chain reserves with their own Aquarius swap before the victim's liquidation lands, changing the collateral units seized per unit of debt repaid, then trade back. Every strategy path that converts at market price (`multiply`, `swap_debt`, `swap_collateral`, `repay_debt_with_collateral`) carries a user-set `min_out` inside the `routeXdr` enforced by the router (`SlippageExceeded`); `liquidate` is the one monetary entrypoint where the output bound is missing. [1](#0-0) 

### Finding Description
`liquidate(env, liquidator, account_id, debt_payments, seize_mode)` takes the payment amounts as input but derives the seized collateral entirely inside `positions::liquidation::process_liquidation` / `liquidation/math.rs` from prices cached in the `Context` during the same transaction. The signature exposes no parameter analogous to the audit fix's `_maxCurrencyAmount` - the caller cannot express "revert if I receive fewer than X units of collateral." [1](#0-0) 

Prices resolve through the price-aggregator pipeline, whose sources include Aquarius pool state read live on-chain: `aquarius_pool_reserves_call` returns raw `get_reserves()` output, and LP fair value is computed from those reserves (`fair_stable_lp_price_wad` multiplies the invariant `D` by the lower leg price over share supply). Reserves, and therefore the derived price, move whenever anyone trades against the pool. [2](#0-1) [3](#0-2) 

The `get_liquidation_estimate` view shows expected seizure, but it is a separate non-atomic read - the estimate's prices are not bound to the execution transaction, mirroring the Crowdinvesting gap between quoting and `buy`. [4](#0-3) 

By contrast, every routed strategy does carry the bound: the controller requires `min_out` inside the swap payload (`total_out < total_min_out → SlippageExceeded`) plus positive measured output, so those paths are not analogs. [5](#0-4) 

### Impact Explanation
A liquidator commits `debt_payments` of real tokens. If the collateral-to-debt price ratio shifts adversely before execution, the same payment seizes fewer collateral units, so the liquidator pays above market for the seizure - a direct loss of user funds bounded by how far the price can move while still passing the sanity band and dual-leg tolerance (single-source bands allow up to ~10% half-width, and two in-band reports can differ by ratio `u = max/min` up to ~1.222). Symmetrically, an attacker who is itself the liquidator can depress the collateral price first, seize more units per debt repaid than the intended bonus allows, and extract the excess from the borrower at near-true-market cost. Either direction converts the missing bound into theft of user funds, not merely a DoS. [6](#0-5) 

### Likelihood Explanation
The attack needs a market whose accepted price leg depends on Aquarius reserves shallow enough to move within the tolerance/sanity gates at a cost below the extracted skew. Fair-value LP pricing dampens reserve manipulation (price scales with `D` and the min leg price), so the strongest case is a constant-product leg or a thin stable pool; the threat model itself bounds in-band report ratios rather than excluding on-chain-derived prices. The attacker's full path is unprivileged: own Aquarius swap → victim's or own `liquidate` → own back-run swap. Cost is AMM fees plus price impact on the attacker's own round-trip; profit is the seized-value delta. [7](#0-6) [8](#0-7) 

### Recommendation
Add a caller-supplied bound to `liquidate`, e.g. a `min_seized: Vec<(HubAssetKey, i128)>` (asset units for `SeizeMode::Transfer`, RAY shares for `Credit`) or a `max_debt_value_wad` cap on the USD value of `debt_payments`, and revert if the computed plan violates it - the same shape as the `_maxCurrencyAmount` / `min_out` fix in the referenced report and the `routeXdr` `min_out` already used by the strategy paths. Additionally consider a liquidation-only staleness/deviation check comparing the execution price to the price leg used by `get_liquidation_estimate` is not enforceable cross-transaction; the bound parameter is the correct fix. [1](#0-0) 

### Proof of Concept
1. Governance lists collateral `C` (e.g., an Aquarius LP or a token priced via an Aquarius constant-product leg) and debt `D`; account `V` is liquidatable with HF < 1.
2. Attacker observes liquidator `L`'s pending `liquidate(L, V, [(D, amt)], SeizeMode::Transfer)` tx.
3. Attacker submits an Aquarius swap on the pool backing `C`'s price leg, pushing the reported `C` price up (or `D` down) while remaining within the feed's tolerance and sanity band (`[min_sanity_price_wad, max_sanity_price_wad]`, dual-leg tolerance). [9](#0-8) 
4. `L`'s `liquidate` executes: `debt_payments` of `amt` are pulled, but the pro-rata plan computed at the manipulated `Context`-cached prices seizes fewer `C` units than the `get_liquidation_estimate` `L` saw. No bound exists to revert. [1](#0-0) 
5. Attacker swaps back in the Aquarius pool, keeping the extracted difference; `L` paid above market for the seized collateral.

Caveat: I verified the missing bound in the `liquidate` signature and the live-reserve reads feeding prices, but did not fully trace `positions/liquidation/math.rs` leg-by-leg or confirm which deployed oracles actually use Aquarius-derived legs; if all production collateral prices are purely Reflector/RedStone feeds, the manipulation path reduces to third-party oracle honesty within bands, which is out of scope - the missing-bound design flaw in `liquidate` stands regardless, since no other entrypoint leaves a committed payment's output fully oracle-determined.

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

**File:** contracts/controller/src/lib.rs (L470-477)
```rust
    fn get_liquidation_estimate(
        env: Env,
        account_id: u64,
        debt_payments: Vec<(HubAssetKey, i128)>,
        seize_mode: SeizeMode,
    ) -> LiquidationEstimate {
        views::liquidation_estimations_detailed(&env, account_id, &debt_payments, seize_mode)
    }
```

**File:** common/src/oracle/providers/aquarius.rs (L45-57)
```rust
pub fn aquarius_pool_reserves_call(env: &Env, pool: &Address) -> Option<(i128, i128)> {
    let reserves = match AquariusPoolClient::new(env, pool).try_get_reserves() {
        Ok(Ok(reserves)) => reserves,
        _ => return None,
    };
    if reserves.len() != 2 {
        return None;
    }
    Some((
        i128::try_from(reserves.get_unchecked(0)).ok()?,
        i128::try_from(reserves.get_unchecked(1)).ok()?,
    ))
}
```

**File:** common/src/oracle/lp_stable.rs (L96-109)
```rust
    let xa_wad = try_amount_to_wad(env, a.reserve, a.decimals)?;
    let xb_wad = try_amount_to_wad(env, b.reserve, b.decimals)?;
    let d = solve_stable_d(env, xa_wad, xb_wad, amp)?;

    let min_price = a.price_wad.min(b.price_wad);
    let share_supply_wad = try_amount_to_wad(env, supply.total_shares, supply.decimals)?;
    if share_supply_wad <= 0 {
        return Err(OracleError::InvalidPrice);
    }

    let fair = d
        .mul(&U256::from_u128(env, min_price as u128))
        .div(&U256::from_u128(env, share_supply_wad as u128));
    try_u256_to_i128(&fair).ok_or(OracleError::InvalidPrice)
```

**File:** skills/xoxno-swap-aggregator/composition.md (L152-160)
```markdown
## How the controller uses the router

The controller never checks a minimum output. The only slippage floor is
`amounts[min_out]` inside `routeXdr`, enforced by the router before payout
(`execute/mod.rs`: `total_out < total_min_out → SlippageExceeded`); the controller then
credits its measured output-balance delta, and the verb's own risk checks
(`strategy_finalize`) apply the same LTV / health-factor gates as a manual borrow. The
`swap_tokens` auth and measurement sequence is in
[`strategies/swap.rs`](../../contracts/controller/src/strategies/swap.rs).
```

**File:** docs/explanation/threat-model.md (L187-210)
```markdown
## Price integrity and availability

Two configured price legs must both be usable and agree within tolerance;
one surviving leg is not a fallback. A single-source key has no top-level
agreement check, although its transitive source may have multiple dependencies.
Sanity bands constrain accepted prices but cannot establish economic correctness.

A single-source feed can report any price `p` in its band `[min, max]`. Two
reports `p1` and `p2` in the same band have `p1 / p2 <= u = max / min`. The
10% single-source cap gives `u <= 11/9`, which is about 1.222. The true NAV
`P` is also in the band, so `P / p <= u`.

Lender safety depends only on the reported collateral prices. Bad debt occurs
only when the reported collateral is less than the debt. Take one collateral
leg with `n` units and a debt `D`. A borrow at the reported price `p1` gives
`D <= LTV * n * p1`. Bad debt at a later reported price `p2` needs
`n * p2 < D`. Both conditions need `p1 / p2 > 1 / LTV >= 1 / LT`. When
`LT < 1 / u`, `1 / LT > u`, and the band does not allow this ratio. An account
that is healthy at a report `p1` has `D <= LT * n * p1`, so the same result
applies from that report. A liquidation does not decrease the units held for
each unit of debt, so the result also applies after a liquidation. Thus
lenders cannot lose while `LT < 1 / u`. The band ratio `u` is the threshold,
not the price deviation. The Liqvid hub has LT 60% or 53% and `u` at most
11/9, so it has a large margin.
```

**File:** contracts/price-aggregator/README.md (L14-23)
```markdown
## Three gates

1. **Stale** (`PriceFeedStale`) — a leg is older than its feed's
   `max_stale_seconds` or the asset's `max_price_stale_seconds`, or two market
   legs differ in age by more than `MAX_LEG_AGE_SPREAD_SECONDS`
2. **Disagree** (`UnsafePriceNotAllowed`) — two legs fall outside the tolerance
   band, or one of two legs has no reading
3. **Sanity** — the final WAD USD price is not positive (`InvalidPrice`) or is
   outside `[min_sanity_price_wad, max_sanity_price_wad]` (`SanityBoundViolated`)

```
