### Title
LP collateral price derived from live, manipulable Aquarius pool reserves enables single-transaction oracle manipulation - (File: contracts/price-aggregator/src/providers/aquarius.rs)

### Summary
The price-aggregator prices Aquarius LP share tokens from the pool's *current* reserves (`get_reserves`), current `total_shares`, and current amplification coefficient, combined with external leg prices. There is no TWAP, no historical observation, and no smoothing: a single unprivileged swap (or direct token transfer to the pool, if reserves are balance-derived) inside one transaction changes the reserves the aggregator reads, and therefore changes the collateral/debt valuation used by the controller's health-factor and liquidation logic in the same transaction. This is the same bug class as the Curve `get_dy()` spot-price oracle in the external report — a manipulable on-chain pool state used as the price source for a lending protocol.

### Finding Description
`read()` in `contracts/price-aggregator/src/providers/aquarius.rs` (lines 90–113) fetches `reserve_a`, `reserve_b`, `total_shares`, and `amp` via live cross-contract calls and feeds them into `fair_lp_price_wad` (constant product) or `fair_stable_lp_price_wad` (stable):

```rust
let (reserve_a, reserve_b) =
    aquarius_pool_reserves_call(&env, &lp.pool).ok_or(OracleError::NoLastPrice)?;
let price_wad = if stable {
    let amp = aquarius_amp_call(&env, &lp.pool).ok_or(OracleError::NoLastPrice)?;
    fair_stable_lp_price_wad(&env, &leg_a, &leg_b, &supply, amp)?
} else {
    fair_lp_price_wad(&env, &leg_a, &leg_b, &supply)?
};
```

`fair_lp_price_wad` in `common/src/oracle/lp.rs` (lines 72–86) computes `2 * sqrt(value_a * value_b) * WAD / share_supply_wad`, and the stable path uses `min(price_a, price_b) * D(reserves)` where `D` is the StableSwap invariant solved from the current reserve tuple. Both are monotone in the reported reserves, so:

- **Downward manipulation (any unprivileged user):** swapping one side of the pool to skew the reserves lowers `min(va, vb)`/`D` for the stable formula (a deeply one-sided book collapses the invariant toward ~2× the smaller leg), and for constant-product pools the only guard is `lp.min_pool_value_wad` — a minimum *total* value check that a skewed-but-large pool still passes. Because `resolve_nested` leg prices are unaffected, the depressed LP price is returned with a valid timestamp and passes the sanity band if the band is wide (production configs use e.g. 1.74–2.44 WAD, a ±~17% band, per `configs/ops/mainnet/*.json` `set_oracle` ops).
- **Upward manipulation:** if `get_reserves` reflects token balances (as the `MockAquariusPool` stub and typical AMM accounting do, since Aquarius accounts reserves from balances), directly transferring one underlying token to the pool contract raises `va` without raising `total_shares`, inflating `sqrt(va * vb)` and thus the LP share price — within the configured sanity band this mints inflated collateral value.

The read re-validates only structural bindings (share id, token order, decimals, pool type, positive reserves) — none of which a swap or donation violates — so the manipulated observation is returned as a normal price to `engine::resolve` and consumed by controller paths that value LP-token collateral/debt (`liquidate`, `borrow`, `update_account_threshold` health checks).

### Impact Explanation
- A depressed LP price pushes LP-collateralized borrowers below their liquidation threshold, letting the attacker liquidate them and capture the HF-based liquidation bonus — theft of user collateral via an unfair liquidation, reachable by any address through `controller::liquidate` plus an Aquarius swap in the same transaction.
- An inflated LP price (donation route) lets the attacker `supply` LP shares and `borrow` more than the collateral's true value, then walk away — protocol insolvency / theft of lender funds.

### Likelihood Explanation
Requires an LP-token market priced via `AquariusLp`/`AquariusStableLp` (production ops configs show such oracles are live on mainnet), pool liquidity shallow enough relative to the attacker's capital to move reserves materially within the sanity band, and either underwater-able LP positions (downward path) or borrowable liquidity (upward path). No privileges, no leaked keys, no off-chain components are needed — the manipulation is a plain swap/transfer by the attacker. The residual constraint is the sanity band and the pool's own liquidity, which bounds but does not eliminate the manipulation, so the realistic severity is Medium-to-High depending on pool depth and band width.

### Recommendation
Make LP pricing robust to single-transaction reserve manipulation:
- Use a manipulation-resistant reserve input: e.g., require the observation to come from a pool TWAP/cumulative oracle if Aquarius exposes one, or price the LP as `min` over several blocks instead of the instantaneous `get_reserves`.
- Bound imbalance: reject the read when `reserve_a`/`reserve_b` deviates from a configured ratio band (for stable pools) or when the implied spot price `reserve_b/reserve_a` deviates from the ratio of the external leg prices `price_a/price_b` by more than a tolerance — a skewed book then fails closed rather than returning a manipulated price.
- For the donation path, compare `get_reserves` against internally tracked reserves or require the pool's own accounting (not raw balances) before trusting the values.

### Proof of Concept
1. Victim supplies Aquarius stable-LP shares as collateral and borrows; their HF is close to the threshold.
2. Attacker calls the pool's `swap` (or `remove_liquidity`/`imbalanced withdraw`) driving `reserve_a` → near 0 and `reserve_b` → large, still keeping pool value ≥ `min_pool_value_wad` (production value is 1e24 WAD).
3. `fair_stable_lp_price_wad` now computes a much smaller invariant `D` against the unchanged `min(price_a, price_b)`, so the LP share `price_wad` drops below the victim's liquidation threshold while remaining inside `[min_sanity_price_wad, max_sanity_price_wad]`.
4. In the same transaction the attacker calls `controller::liquidate` on the victim, seizes collateral with the liquidation bonus at the depressed valuation, then swaps back to restore the pool. Net: victim's collateral is seized at an artificially low price — theft proportional to position size times (true price − manipulated price + bonus).