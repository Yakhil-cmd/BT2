### Title
Aquarius LP collateral price is derived from manipulable live pool reserves, allowing over-borrowing and bad debt - ([File: contracts/price-aggregator/src/providers/aquarius.rs](contracts/price-aggregator/src/providers/aquarius.rs))

### Summary
The price aggregator prices Aquarius LP share collateral by reading the pool's live reserves (`get_reserves`) and total shares at read time and computing a fair value. Because `get_reserves` reflects the pool's current token balances, an unprivileged attacker can inflate the reported reserves (proportional direct token transfers / donations to the pool) inside the same transaction that supplies LP collateral and borrows, pushing the derived LP price up to the oracle's `max_sanity_price_wad` bound — which mainnet configs set as wide as 10x (`min_sanity_price_wad` 2.5e19 → `max_sanity_price_wad` 2.5e20 with `tolerance` 0). The attacker then repays nothing, withdraws their donated liquidity back out of the Aquarius pool, and leaves the lending market with under-collateralized debt. This is the direct analog of the Uniswap-quoter spot-price manipulation bug class.

### Finding Description
`aquarius::read` resolves the two leg prices via `engine::resolve_nested`, then reads `(reserve_a, reserve_b)` from `aquarius_pool_reserves_call` (a `get_reserves` cross-contract call) and `total_shares` from `get_total_shares` in the same transaction as the consuming lending action [1](#0-0) . The fair value is `2*sqrt(value_a*value_b)/share_supply` for constant-product pools [2](#0-1)  and `D * min(price_a, price_b) / share_supply` for stable pools [3](#0-2) .

Both formulas scale linearly with reserves relative to a fixed share supply. Proportionally inflating both reserves by a factor `f` without minting shares scales the derived share price by `f`. `get_reserves` reflects live pool balances (the in-repo mock returns `token::balance(&pool)` [4](#0-3) ), so direct token transfers to the pool address raise the computed price; an attacker holding the dominant share of the pool recovers nearly the entire donation on `withdraw`.

The only bounds are the absolute sanity band checked in `Outcome::failure` [5](#0-4)  — for single-source LP oracles there is no second leg, so `Legs::One` bypasses the dual-leg tolerance check entirely [6](#0-5) , and `min_pool_value_wad` is only a floor [7](#0-6) . Deployed mainnet oracles are single-source with `tolerance` 0/0 and sanity bands up to an order of magnitude wide (e.g. `min 25000000000000000000`, `max 250000000000000000000`) [8](#0-7) . The Context-cached price feeds health factor and `min_borrow_collateral_usd` for `supply`/`borrow`/`withdraw`, so the inflated price directly authorizes over-borrowing.

### Impact Explanation
Protocol insolvency / theft of user funds. The attacker inflates the LP collateral price (bounded only by `max_sanity_price_wad`, up to ~10x on listed markets), supplies LP shares, calls controller `borrow` and `withdraw` for the maximum the inflated valuation permits, then unwinds the Aquarius position to reclaim the donated reserves. The position is left under-collateralized; `clean_bad_debt` writes the shortfall into the supply index, socializing the loss across suppliers.

### Likelihood Explanation
High. Every step is reachable by a single unprivileged address in one transaction: `deposit`/token transfers into the Aquarius pool (own trades/donations), `supply`, `borrow`, `withdraw`, then `withdraw`/`swap` on Aquarius to recover capital. No privileged access, leaked keys, or third-party oracle dishonesty is required; the Aquarius pool honestly reports its real, manipulated balances. Net attack cost is only the donation share leaked to other LPs plus pool fees, which tends to zero as the attacker's share of the pool approaches 100% (reachable via deposited liquidity, including flash-funded capital).

### Recommendation
Do not derive collateral value from raw pool balances that can be donated. Use manipulation-resistant inputs: e.g., require Aquarius pools to expose tracked (non-balance) reserves, cross-check LP price against a second independent source via the dual-leg tolerance mechanism (require `is_dual()` for LP collateral oracles), tighten `min/max_sanity_price_wad` to a narrow band around a time-anchored reference, or price LP collateral off a TWAP/virtual-price observation rather than instantaneous reserves.

### Proof of Concept
Conceptual sequence (single transaction, unprivileged):

1. Attacker deposits `A`/`B` into the Aquarius constant-product pool, receiving LP shares until they hold the dominant share fraction.
2. Attacker transfers additional `A` and `B` directly to the pool address (no shares minted), raising `(reserve_a, reserve_b)` proportionally by factor `f` — `fair_lp_price_wad` now returns `f ×` the honest price, still below `max_sanity_price_wad` for `f` up to ~10.
3. Controller `supply` of the LP shares, then `borrow`/`withdraw` up to the inflated collateral valuation; HF passes because the Context-cached `price_wad` was read at inflated reserves.
4. Attacker calls Aquarius `withdraw`, redeeming their shares for reserves including the donation (minus the small fraction owned by other LPs).
5. Price snaps back; the borrowed tokens are kept, the position holds bad debt, and `clean_bad_debt` socializes the loss into the supply index.

Caveat: this assumes Aquarius `get_reserves` returns live token balances, consistent with the in-repo mock [4](#0-3) ; if the production pool returns internally stored reserves immune to donations, the donation leg fails, though reserve inflation via swaps still moves the fair price in the imbalanced direction for single-sided manipulation and the finding retains validity as a spot-reserve dependence.

### Citations

**File:** contracts/price-aggregator/src/providers/aquarius.rs (L88-114)
```rust
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

**File:** contracts/price-aggregator/src/providers/aquarius.rs (L118-122)
```rust
    let pool_value_wad = try_mul_div_half_up(&env, price_wad, total_shares, share_unit)
        .ok_or(OracleError::InvalidPrice)?;
    if pool_value_wad < lp.min_pool_value_wad {
        return Err(OracleError::InsufficientAquariusLiquidity);
    }
```

**File:** common/src/oracle/lp.rs (L75-86)
```rust
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

**File:** contracts/swap-aggregator/tests/unit/support/mocks.rs (L218-224)
```rust
        pub fn get_reserves(env: Env) -> Vec<u128> {
            let pool = env.current_contract_address();
            let tokens = Self::get_tokens(env.clone());
            let r0 = token::Client::new(&env, &tokens.get(0).unwrap()).balance(&pool);
            let r1 = token::Client::new(&env, &tokens.get(1).unwrap()).balance(&pool);
            vec![&env, r0 as u128, r1 as u128]
        }
```

**File:** contracts/price-aggregator/src/engine.rs (L142-146)
```rust
        if self.price_wad < oracle.min_sanity_price_wad
            || self.price_wad > oracle.max_sanity_price_wad
        {
            return Some(OracleError::SanityBoundViolated);
        }
```

**File:** contracts/price-aggregator/src/engine.rs (L504-516)
```rust
    let first = read_source(
        session,
        key,
        oracle,
        &oracle.sources.get_unchecked(0),
        depth,
    )?;
    if count == 1 {
        return Ok(match first {
            Some(r) => Legs::One(r),
            None => Legs::Empty,
        });
    }
```

**File:** configs/ops/mainnet/b578b28c83e106702d956ffecc40d10d7187c34db0f56dd6243d2fc841ea8d9e.json (L37-45)
```json
        ],
        "tolerance": {
          "upper_ratio_bps": 0,
          "lower_ratio_bps": 0
        },
        "independence": "RequireDisjoint",
        "min_sanity_price_wad": "25000000000000000000",
        "max_sanity_price_wad": "250000000000000000000"
      }
```
