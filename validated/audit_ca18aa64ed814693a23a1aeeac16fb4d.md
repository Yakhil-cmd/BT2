### Title
In-band oracle drift on the high-LTV stables spoke permits borrowing into protocol bad debt - ([File: configs/mainnet/spokes.json])

### Summary
The bug class from the Ubiquity report — collateral priced at a temporarily elevated USD value mints/borrows obligations that become unbacked when the price normalizes — maps onto XOXNO Lending as follows: the "Stables & FX" spoke (id 5) lists USDC at `ltv 8800 / liquidation_threshold 9200`, EURC at `8400/8800`, PYUSD at `8600/9000`, and USDT0 at `8400/8800` [1](#0-0) . The oracle sanity bands accept any honest price inside a wide interval: USDC `[0.95, 1.05]` [2](#0-1)  and EURC `[1.06, 1.22]` WAD [3](#0-2) . The protocol's own safety proof only covers a single collateral leg with debt priced at true value, and explicitly notes that when the debt feed also moves in its band, "the effective `u` is the product of the two band ratios" — a case where the bound no longer holds [4](#0-3) .

### Finding Description
`require_post_pool_risk_gates` only enforces `ltv_collateral >= total_debt`, `health_factor >= 1 WAD`, and the min-collateral floor, all computed from `Context`-cached reported prices [5](#0-4) . Collateral value is floored and debt is ceiled at the *reported* price [6](#0-5) . Nothing constrains borrowing when the collateral or debt asset is trading away from peg inside its sanity band — the bands are intentionally wide enough to keep honest feeds resolvable during drift.

The threat-model invariant requires `LT < 1/u` for lender safety. For the two-sided case `u_eff = u_collateral * u_debt`. With USDC `u = 1.05/0.95 = 1.105` and EURC `u = 1.22/1.06 = 1.151`, `u_eff = 1.272`, while `1/LT_USDC = 1/0.92 = 1.087`. Since `1.272 > 1.087`, the documented precondition for "lenders cannot lose" is violated on spoke 5.

Concrete path for a single unprivileged account:
1. `supply` USDC on spoke 5 while the reported USDC price is near band top (1.05).
2. `borrow` EURC up to max LTV while the reported EURC price is near band floor (1.06).
3. Prices drift honestly within bands: USDC reports ~0.95, EURC reports ~1.22. Collateral value falls to `0.95n` while debt rises to `0.88 * 1.05n / 1.06 * 1.22 = 1.063n` — the account is ~12% undercollateralized.
4. `liquidate` (insolvent branch caps repayment at what `C` backs) followed by `clean_bad_debt` writes the shortfall into the supply index, socializing the loss to USDC lenders; `recapitalize` is the fallback [7](#0-6) .

No oracle dishonesty is required — every report is a valid honest price inside its band and inside dual-leg tolerance. The same exposure exists for USDC collateral vs USDC debt (single-sided `u=1.105` vs `1/LT=1.087` leaves only a thin margin fully consumed by one index accrual) and for PYUSD/USDT0 legs at LT 88–90%.

### Impact Explanation
Protocol insolvency: when `C < D` at liquidation the seizure is capped at what collateral backs, and the residual debt is cleared via `clean_bad_debt` / supply-index write-down, i.e., direct loss of supplier principal on hub assets. Worst-case shortfall from a fresh max-LTV borrow is roughly `(LTV * u_eff) - 1 ≈ 11.9%` of the collateral's band-floor value, bounded by spoke-5 borrow caps.

### Likelihood Explanation
Requires a relative move between two stable feeds that stays inside both sanity bands — e.g., a moderate USDC depeg toward $0.95 combined with EURUSD appreciation toward €1 = $1.22. Both endpoints are real historical levels, and the drift requires no attacker action after the borrow, no oracle manipulation, and no privileged call. It is not a same-block exploit; it is a structural gap between configured LT and configured bands.

### Recommendation
Enforce the documented invariant `LT < 1/u_eff` per market pair: either raise the collateral-side band tightness, lower spoke-5 `ltv`/`liquidation_threshold` (e.g., USDC LT below ~78% under the current bands), or add a per-asset "peg guard" that scales effective LTV by the price's position inside its sanity band (discounting collateral priced near band top and up-weighting debt priced near band floor), analogous to the report's suggested price-range check.

### Proof of Concept
1. Governance config as deployed: spoke 5 USDC LTV 88% / LT 92% [8](#0-7) ; USDC band `[0.95, 1.05]` and EURC band `[1.06, 1.22]` [3](#0-2) .
2. Attacker supplies `n` USDC when feeds report 1.05 → `ltv_collateral = 1.05n`.
3. `borrow(spoke5, EURC, amount)` where `amount * 1.06 = 0.88 * 1.05n` — passes `ltv_collateral >= total_debt` and `HF = 0.92*1.05n / 0.924n ≈ 1.045 >= 1` [9](#0-8) .
4. Markets drift: USDC reports 0.95 (in band, resolvable), EURC reports 1.22 (in band, resolvable). New totals: `W = 0.92 * 0.95n = 0.874n`, `D = (0.924n/1.06) * 1.22 = 1.0635n`, `C = 0.95n`.
5. `HF ≈ 0.822 < 1` and `C < D` → `is_liquidatable` true; liquidation takes the insolvent `C`-backed quote [7](#0-6) , leaving ~0.11n USD of unpayable debt cleared by `clean_bad_debt` supply-index write-down — a direct loss to USDC suppliers, matching the report's undercollateralization outcome.

### Citations

**File:** configs/mainnet/spokes.json (L376-418)
```json
      "USDC": {
        "hub_id": 1,
        "can_be_collateral": true,
        "can_be_borrowed": true,
        "ltv": 8800,
        "liquidation_threshold": 9200,
        "liquidation_bonus": 400,
        "supply_cap": "149600000000000",
        "borrow_cap": "112200000000000",
        "liquidation_fees": 1000
      },
      "EURC": {
        "hub_id": 1,
        "can_be_collateral": true,
        "can_be_borrowed": true,
        "ltv": 8400,
        "liquidation_threshold": 8800,
        "liquidation_bonus": 400,
        "supply_cap": "13000000000000",
        "borrow_cap": "9750000000000",
        "liquidation_fees": 1000
      },
      "PYUSD": {
        "hub_id": 1,
        "can_be_collateral": true,
        "can_be_borrowed": true,
        "ltv": 8600,
        "liquidation_threshold": 9000,
        "liquidation_bonus": 300,
        "supply_cap": "2000000000000",
        "borrow_cap": "1500000000000",
        "liquidation_fees": 1000
      },
      "USDT0": {
        "hub_id": 1,
        "can_be_collateral": true,
        "can_be_borrowed": true,
        "ltv": 8400,
        "liquidation_threshold": 8800,
        "liquidation_bonus": 400,
        "supply_cap": "1000000000000",
        "borrow_cap": "750000000000",
        "liquidation_fees": 1000
```

**File:** configs/mainnet/markets.json (L155-161)
```json
        "tolerance": {
          "upper_ratio_bps": 10500,
          "lower_ratio_bps": 9524
        },
        "independence": "RequireDisjoint",
        "min_sanity_price_wad": "950000000000000000",
        "max_sanity_price_wad": "1050000000000000000"
```

**File:** configs/mainnet/markets.json (L216-222)
```json
        "tolerance": {
          "upper_ratio_bps": 10500,
          "lower_ratio_bps": 9524
        },
        "independence": "RequireDisjoint",
        "min_sanity_price_wad": "1060000000000000000",
        "max_sanity_price_wad": "1220000000000000000"
```

**File:** docs/explanation/threat-model.md (L199-217)
```markdown
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

This result has limits. It applies to one collateral leg. It prices the debt
at its true value. If the debt feed can also move in its own band, the
effective `u` is the product of the two band ratios. It does not include
interest that accrues after the borrow. When governance moves the band, the
result applies again only from a report in the new band at which the account
is healthy.
```

**File:** contracts/controller/src/risk/validation.rs (L34-58)
```rust
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

**File:** skills/xoxno-lending/math.md (L266-276)
```markdown
```text
for each supply position:
  value_hup   = position_value(shares, supply_index, price)          // half-up
  value_floor = position_value_floor(shares, supply_index, price)
  effective_ltv = min(loan_to_value_bps, liquidation_threshold_bps)
  total_collateral    += value_hup
  ltv_collateral      += floor(value_floor × half_up(effective_ltv × WAD / BPS) / WAD)
  weighted_collateral += floor(value_floor × half_up(liquidation_threshold × WAD / BPS) / WAD)
for each debt position:
  total_debt += position_value_ceil(shares, borrow_index, price)
health_factor_wad = total_debt == 0 ? i128::MAX : floor(weighted_collateral × WAD / total_debt)   // saturating at i128::MAX
```

**File:** skills/xoxno-lending/math.md (L339-341)
```markdown
if cap and C < D:      quote = (min(D, floor(C × WAD / (WAD + base_wad))), base)  // insolvent: what C backs
elif cap and cap < base: quote = (D, max(cap, 0))                            // band D ≤ C < D × (1 + base)
else:                  b = cap ? min(bonus, cap) : bonus
```
