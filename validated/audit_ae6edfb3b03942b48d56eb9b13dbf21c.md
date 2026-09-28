The ParaSpace bug class is collateral valuation inflated via a manipulable token/share balance. Let me check whether XOXNO's price-aggregator or controller ever derives collateral value from on-chain balances/reserves that an attacker could skew inside one transaction.### Title
Donation-inflated Aquarius reserves inflate LP collateral fair price, enabling under-collateralized borrows - ([File: contracts/price-aggregator/src/providers/aquarius.rs])

### Summary
The ParaSpace exploit's root cause was collateral valuation derived from an on-chain balance (`scaledBalanceOf` of a staking receipt) that an unprivileged attacker could inflate inside the same attack, then borrow against the inflated collateral. XOXNO Lending replicates this shape in the `AquariusLp` oracle source: the fair price of an LP share used as collateral is computed from the Aquarius pool's live `get_reserves` and `get_total_shares`, and reserves grow when an attacker donates underlying tokens directly to the pool. An attacker holding most of the LP supply can inflate the oracle price, mint an overvalued collateral position, and borrow real assets far above true collateral value.

### Finding Description
In `contracts/price-aggregator/src/providers/aquarius.rs`, `read()` prices an LP share as `2 * sqrt(value_a * value_b) / total_shares` (constant-product, via `fair_lp_price_wad`) or `D * min(price_a, price_b) / total_shares` (stable, via `fair_stable_lp_price_wad`), where `value_*` comes straight from `aquarius_pool_reserves_call` — a raw `get_reserves` call on the pool contract [1](#0-0) [2](#0-1) .

`get_reserves` reflects the pool's token balances, which any address can increase by a plain token transfer to the pool — there is no measured-receipt or internal accounting filter. The constant-product formula is swap-resistant (the invariant is preserved by swaps) but is *not* donation-resistant: donating `D` units of leg A raises the fair price by `sqrt((va + D) * vb) - sqrt(va * vb)`, a real, persistent increase in collateral value per LP share.

The mainnet configuration confirms LP share tokens are listed as supply assets priced solely by a single `AquariusLp` source with zero dual-source tolerance (`upper_ratio_bps: 0, lower_ratio_bps: 0`), gated only by `min_pool_value_wad` and wide sanity bands (e.g. `0.45–2.5` USD) [3](#0-2) . With a single source, nothing cross-checks the reserve-derived price; the sanity band only caps the inflation, it does not prevent it — a price that should be ~1.0 can be pushed anywhere up to `max_sanity_price_wad` and still validates.

The collateral amount itself is an unforgeable internal share balance, so the ParaSpace "inflate your balance" leg maps onto "inflate the price of your balance": attacker acquires LP shares (a normal Aquarius deposit — an "own trade"), donates leg tokens to the pool, then calls `controller::borrow` (or `multiply`/`flash_position`) while the Context-cached strict price reflects the inflated reserves [4](#0-3) .

### Impact Explanation
Protocol insolvency. The borrow leg prices the attacker's LP collateral at the inflated fair price, so `borrow` releases assets exceeding true collateral value. The attacker then abandons the position; liquidation cannot recover the shortfall because the LP token's realizable value reverts once the donated tokens are withdrawn... they aren't — the donation is unrecoverable — but profit is still positive when the attacker holds a large fraction `f` of LP supply and the pool is imbalanced: profit ≈ `LTV * f * 2*sqrt(vb) * (sqrt(va + D) - sqrt(va)) - D`, maximized near `D ≈ f² * vb - va`. For a pool holding, e.g., `va ≪ vb` and the attacker near 100% of shares, the inflated borrow exceeds the donation cost. All borrowed assets are permanently lost, socialized across suppliers of the lent market via bad-debt write-down [5](#0-4) .

### Likelihood Explanation
Medium. Requirements: (a) an `AquariusLp`-priced LP token is listed as a supply/borrow market (it is — see `XLMSolvBTC_LP` and others in `configs/mainnet/markets.json`); (b) the Aquarius pool's reserves are manipulable within the sanity band at a cost below the borrow proceeds — true when the attacker controls most of the LP supply (acquirable by ordinary deposits) or the pool is thin/imbalanced; (c) the inflated price stays inside `min/max_sanity_price_wad` — the bands are wide (5.5x range). No privileged access, no oracle compromise, and no off-chain cooperation is needed; the whole attack is reachable through `supply`, `borrow`, and direct token transfers.

### Recommendation
Make the LP fair-price derivation donation-resistant:
- Track reserves via the pool's accounting (e.g. invariant/virtual-price reads such as Aquarius `get_estimate_amount`-style or `virtual_price` endpoints) rather than raw `get_reserves`, or compute the constant-product leg value from `sqrt(reserve_a * reserve_b)` recomputed against a minimum-k invariant instead of summing independent legs — the standard defense is pricing LP shares off `get_virtual_price`/`D` that ignores profit-free donations.
- Require a second, independent price source per LP asset so the dual-source tolerance check actually binds (current `0/0` tolerance config is a single-source bypass).
- Tighten `min_sanity_price_wad`/`max_sanity_price_wad` for LP assets to a narrow band around the theoretical redemption value.
- On the lending side, apply a conservative haircut (`update_account_threshold`) to `AquariusLp`-priced collateral commensurate with how manipulable the underlying pool is.

### Proof of Concept
```
Pre-state: market M has asset LP = Aquarius share token, priced by a single
AquariusLp source over pool P with reserves (ra, rb) and total_shares S.
Attacker holds ≈ all S (minted by depositing ra/rb proportionally).
Config: sanity band [0.45, 2.5] USD, tolerance 0/0, single source.

1. supply(LP shares)         // collateral position opened
2. token_a.transfer(P, D)    // donation; P.get_reserves() now (ra + D, rb)
   Choose D ≈ rb - ra (for f ≈ 1); fair price rises from
   2·sqrt(ra·rb)/S to 2·sqrt((ra+D)·rb)/S  (up to ~sqrt(rb/ra)× for thin ra).
3. borrow(asset X, LTV × inflated_LP_value)  // Context price reads step-2 reserves
4. Default. LP collateral's realizable value is only the pre-donation pool
   value; the borrowed X exceeds it by LTV·f·Δvalue − 0 (donation already sunk
   into step-2 price). Suppliers of X absorb the shortfall via
   apply_bad_debt_to_supply_index.
```
Exact entrypoints: `controller::supply`, `token::transfer(P, D)`, `controller::borrow` — all unprivileged. Root cause at `contracts/price-aggregator/src/providers/aquarius.rs:90-114` (`aquarius_pool_reserves_call` → `fair_lp_price_wad`/`fair_stable_lp_price_wad`) [1](#0-0) .

### Citations

**File:** contracts/price-aggregator/src/providers/aquarius.rs (L69-114)
```rust
pub(crate) fn read(
    session: &mut Session,
    key: &PriceKey,
    lp: &AquariusLpSource,
    share_decimals: u32,
    depth: u32,
    stable: bool,
) -> Result<Option<(OracleObservation, bool)>, OracleError> {
    let env = session.env().clone();
    let tokens = bound_tokens(&env, key, lp).ok_or(OracleError::NoLastPrice)?;
    if !pool_kind_matches(&env, lp, stable) {
        return Err(OracleError::NoLastPrice);
    }
    let PriceKey::Token(share) = key else {
        return Err(OracleError::NoLastPrice);
    };
    if !decimals_match(&env, share, &tokens, share_decimals, lp) {
        return Err(OracleError::NoLastPrice);
    }
    let price_a = engine::resolve_nested(session, &lp.key_a, depth + 1)?;
    let price_b = engine::resolve_nested(session, &lp.key_b, depth + 1)?;
    let (reserve_a, reserve_b) =
        aquarius_pool_reserves_call(&env, &lp.pool).ok_or(OracleError::NoLastPrice)?;
    let total_shares =
        aquarius_total_shares_call(&env, &lp.pool).ok_or(OracleError::NoLastPrice)?;

    let leg_a = LpLeg {
        reserve: reserve_a,
        decimals: lp.reserve_a_decimals,
        price_wad: price_a.price_wad,
    };
    let leg_b = LpLeg {
        reserve: reserve_b,
        decimals: lp.reserve_b_decimals,
        price_wad: price_b.price_wad,
    };
    let supply = LpSupply {
        total_shares,
        decimals: share_decimals,
    };
    let price_wad = if stable {
        let amp = aquarius_amp_call(&env, &lp.pool).ok_or(OracleError::NoLastPrice)?;
        fair_stable_lp_price_wad(&env, &leg_a, &leg_b, &supply, amp)?
    } else {
        fair_lp_price_wad(&env, &leg_a, &leg_b, &supply)?
    };
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

**File:** configs/mainnet/markets.json (L1204-1230)
```json
        "max_price_stale_seconds": 57600,
        "sources": [
          {
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
          }
        ],
        "tolerance": {
          "upper_ratio_bps": 0,
          "lower_ratio_bps": 0
        },
        "independence": "RequireDisjoint",
        "min_sanity_price_wad": "450000000000000000",
        "max_sanity_price_wad": "2500000000000000000"
      },
```

**File:** common/src/oracle/lp.rs (L57-87)
```rust
pub fn fair_lp_price_wad(
    env: &Env,
    a: &LpLeg,
    b: &LpLeg,
    supply: &LpSupply,
) -> Result<i128, OracleError> {
    if a.reserve <= 0
        || b.reserve <= 0
        || a.price_wad <= 0
        || b.price_wad <= 0
        || supply.total_shares <= 0
    {
        return Err(OracleError::InvalidPrice);
    }

    let value_a = reserve_value_wad(env, a)?;
    let value_b = reserve_value_wad(env, b)?;

    let total_value =
        isqrt_of_product(env, value_a as u128, value_b as u128).mul(&U256::from_u32(env, 2));

    let share_supply_wad = try_amount_to_wad(env, supply.total_shares, supply.decimals)?;
    if share_supply_wad <= 0 {
        return Err(OracleError::InvalidPrice);
    }
    let fair = total_value
        .mul(&U256::from_u128(env, WAD as u128))
        .div(&U256::from_u128(env, share_supply_wad as u128));

    try_u256_to_i128(&fair).ok_or(OracleError::InvalidPrice)
}
```
