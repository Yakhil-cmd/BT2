### Title
Spot-reserve Aquarius LP pricing is manipulable within one transaction, and the `min_pool_value_wad` liquidity floor is computed from the same manipulated reserves — (File: contracts/price-aggregator/src/providers/aquarius.rs)

### Summary
The `AquariusLp` and `AquariusStableLp` price sources value LP share tokens from the pool's *current* reserves and total share supply, read at resolution time (`aquarius_pool_reserves_call`, `aquarius_total_shares_call`). There is no TWAP, no smoothing, and no comparison of the derived price against an independent AMM quote — the configured tolerance is `0` for every deployed LP oracle, so the source is effectively unchecked. The only liquidity safeguard, `min_pool_value_wad`, multiplies the just-derived (manipulated) `price_wad` by `total_shares` and therefore passes whenever the manipulation itself inflates the apparent pool value. Sanity bands are the last defense, and several deployed bands are wide (e.g., a ~10x min/max ratio on `CDOY7ILRR7PDGLBXZUPSENB6XOET77PR2JY3HXDGQS3TS4T764OYBUGO` and `CBOHAVUYKQD4C7FIVXEDJCVLUZYUO6RN3VIKEDOTIJGDDV3QN33Y4T4D`).

### Finding Description
In `aquarius::read` (contracts/price-aggregator/src/providers/aquarius.rs:69-131), the LP share price is produced from a single instantaneous snapshot:

```rust
let (reserve_a, reserve_b) = aquarius_pool_reserves_call(&env, &lp.pool)...;
let price_wad = fair_lp_price_wad(&env, &leg_a, &leg_b, &supply)?; // or fair_stable_lp_price_wad
let pool_value_wad = try_mul_div_half_up(&env, price_wad, total_shares, share_unit)?;
if pool_value_wad < lp.min_pool_value_wad { return Err(InsufficientAquariusLiquidity); }
```

Two consequences:

1. **Single-transaction manipulation surface.** For a constant-product pool the fair-price formula scales with the product of reserves, so any action that raises the reserve product without minting LP shares inflates the share price. For a *stable* pool, `fair_stable_lp_price_wad` additionally depends on the reserve *ratio* relative to the amplification coefficient, so a large swap on a thin stable pool moves the derived LP price directly. Because resolution is spot and every LP oracle is single-source with `tolerance = {0, 0}` (see `configs/ops/mainnet/541d5381…json`, `…/a1795e52…json`, `…/e9bd6d1d…json`), there is no second leg to veto a manipulated observation.

2. **The liquidity floor is self-referential.** `pool_value_wad` is `price_wad × total_shares`, i.e. it prices the pool's TVL using the very reserves the attacker controls. Inflating reserves inflates `pool_value_wad` in lockstep, so `InsufficientAquariusLiquidity` can never trigger on the manipulated path — it only protects against genuinely shrinking pools, not against an attacker fattening one.

This is the exact bug class of the USSD report: a DEX-derived price whose reliability rests on liquidity the protocol does not actually verify independently. XOXNO has a liquidity knob (`min_pool_value_wad`), but it measures the manipulated quantity, and thin configured floors (e.g., `200_000e18` on one oracle, `2_500e18` on a testnet config) plus wide sanity bands leave room.

### Impact Explanation
An attacker can push the LP collateral price upward inside the sanity band, then call `controller::supply` with the LP token and `controller::borrow` against the inflated USD value, leaving bad debt — protocol insolvency absorbed by suppliers via `clean_bad_debt`/index write-down. Conversely, deflating the LP price (or inflating a borrowable token's LP-based quote) drops honest positions' health factor, enabling the attacker to `liquidate` them at a discount and seize collateral via the bonus curve. Both are theft of user funds / insolvency, reachable with a single unprivileged transaction: manipulate the Aquarius pool (own swap or direct token transfer to the pool), then in the same or next ledger call `supply`+`borrow` or `liquidate` on the controller.

### Likelihood Explanation
Medium. Exploitation requires (a) the manipulation mechanics to fit inside the configured sanity band — several bands allow ~2x–10x headroom — and (b) reserves that reflect the attacker's action within the same ledger, which holds for any Aquarius pool whose `get_reserves` reflects post-swap or balance-derived state (the constant-product formula only resists *swaps*, not donation-style reserve inflation; the stable-pool formula is also sensitive to swap-induced imbalance on thin pools). The cost is bounded by the pool's real depth, which is precisely what `min_pool_value_wad` was meant to police but cannot, because it is computed from the same reserves. Profit is capped by how much of the inflated collateral value can be borrowed out — with high-LTV hubs this exceeds the manipulation cost whenever pool depth is a fraction of the lending market's book.

### Recommendation
- Compute `pool_value_wad` from the *underlying legs* (`reserve_a × price_a + reserve_b × price_b`) rather than from the derived LP price, and additionally compare current reserves to a stored/attested baseline so a sudden reserve jump trips the floor instead of raising it.
- Require dual sources for LP-priced assets with a nonzero `tolerance` (e.g., an LP fair-value leg plus a conservative spot-quote leg), so a manipulated reserve snapshot must also defeat an independent reference.
- Tighten `min_sanity_price_wad`/`max_sanity_price_wad` bands on LP oracles to a fraction of current value rather than the observed ~10x ranges, and raise `min_pool_value_wad` to a value proportionate to the borrowable depth of each market.
- Prefer an `IndependencePolicy::RequireDisjoint` second source on a venue other than the same Aquarius pool.

### Proof of Concept
```text
Preconditions: market M lists Aquarius LP token L as collateral with a single
PriceSource::AquariusLp source, tolerance {0,0}, sanity band wide enough to
admit a k× price move, min_pool_value_wad F.

1. Attacker acquires L tokens (add liquidity to the Aquarius pool).
2. Attacker inflates the pool's reserve product — e.g., transfers a large
   amount of token_a (or token_b) directly to the pool so get_reserves()
   reflects the donation, or executes a swap that moves a thin stable pool's
   reserves off peg — such that:
       new price_wad' <= max_sanity_price_wad   (still inside the band)
   and simultaneously:
       pool_value_wad' = price_wad' * total_shares > F   (floor still passes,
       because it is computed from the same inflated reserves)
3. Attacker calls controller::supply(L, amount) at the manipulated price.
4. Attacker calls controller::borrow(debt_asset, X) with X backed by the
   inflated collateral USD value (HF computed from Context-cached strict
   prices that now include price_wad').
5. Attacker withdraws X, abandons the LP collateral, and restores the pool
   (swap back / let arbitrage rebalance). The position is now undercollateralized.
6. clean_bad_debt writes the loss into the supply index → suppliers absorb it.

Mirror variant (liquidation): manipulate the LP price downward within
min_sanity_price_wad, call controller::liquidate on now-underwater honest
positions, seize collateral at the HF-based bonus, restore the pool.
```

Uncertainty note: step 2's donation leg depends on whether Aquarius `get_reserves` reflects raw token balances or internally synced reserves; if it is sync-gated, the stable-pool swap-skew path remains the live vector on thin pools. The self-referential `min_pool_value_wad` flaw holds regardless of which manipulation primitive is used.