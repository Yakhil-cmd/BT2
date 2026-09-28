### Title
LP-collateral valuation is snapshotted before the in-flight swap moves the underlying Aquarius pool — (File: contracts/controller/src/strategies/multiply.rs)

### Summary
The controller caches oracle prices once per invocation in `Context` before a strategy executes its swap route, then runs the post-action solvency/health gate against those stale prices. When a collateral asset is priced via an `AquariusLp`/`AquariusStableLp` source, its price is derived from live pool reserves (`2*sqrt(va*vb)/total_shares`), which the attacker's own router hops can move inside the same transaction after the snapshot. The final risk gate therefore values collateral at the pre-swap price while the account's real collateral value has already changed — the same "value at snapshot, settle after the move" class as the DeliHook pre-swap fee conversion.

### Finding Description
Every account-mutating strategy (`multiply`, `swap_debt`, `swap_collateral`, `repay_debt_with_collateral`) calls `prefetch_strategy_prices`, which populates `cache.token_prices` exactly once; `fetch_prices` skips already-cached assets and `cached_price` never re-reads the aggregator. In `process_multiply` the order is:

1. `prefetch_strategy_prices` — collateral price cached (line 65)
2. `borrow_into_controller` — debt minted (line 76)
3. `swap_tokens_or_passthrough` → `swap_tokens` → `router.execute_strategy` — attacker-supplied route executes on Aquarius pools (lines 90-97; `contracts/controller/src/strategies/swap.rs` lines 34-38)
4. `process_deposit`, then `strategy_finalize` → `enforce_post_pool_solvency` — HF computed with the step-1 price (line 112)

The price-aggregator's Aquarius provider reads `get_reserves`/`get_total_shares` live at call time (`contracts/price-aggregator/src/providers/aquarius.rs` lines 90-113) and `fair_lp_price_wad` computes `2*sqrt(value_a*value_b)/shares` (`common/src/oracle/lp.rs` lines 72-84), so the LP price is a function of reserves the swap itself mutates. Venue adapters are unallowlisted from the caller's perspective — the attacker encodes arbitrary Aquarius hops in `swap`/`convert_swap`. A large skewing swap through the pool backing the LP collateral changes its fair value by roughly the square root of the reserve-ratio change, but the Context keeps the pre-swap valuation for `enforce_post_pool_solvency`, `sum_debt_usd`/`position_value`, and the LTV-weighted collateral checks (`contracts/controller/src/risk/totals.rs` lines 47-58, `contracts/controller/src/context.rs` lines 142-160).

The same shape applies to `swap_debt` (price of `existing_debt`/`new_debt` cached before the repay-leg swap) and `swap_collateral` (destination `new` collateral price cached before the route runs).

### Impact Explanation
An attacker supplies LP-token collateral, primes nothing — the priming is the strategy's own route: they call `multiply` (or `swap_collateral`) with a route whose Aquarius hop skews the reserves of the pool backing their collateral's oracle in the unfavorable direction (depressing the LP fair value). The post-swap solvency gate still prices collateral at the pre-move fair value, so the account passes `HF >= 1` while its true post-state collateral is worth less. The excess borrowed debt is extracted as real tokens; the position is immediately undercollateralized at any fresh price read, becomes bad debt, and `clean_bad_debt`/supply-index write-down socializes the shortfall onto suppliers. Impact class: protocol insolvency / theft of pool funds.

Symmetrically, biasing the LP fair value upward post-check direction is bounded by the same sqrt damping; the profitable direction is inflating the cached (checked) value relative to realizable value — i.e., deposit LP collateral, then within the same strategy call crash the pool's fair value after the snapshot while the gate still sees the high price, having borrowed against it.

### Likelihood Explanation
Requirements: a market whose oracle is an `AquariusLp`/`AquariusStableLp` source that is borrowable-against collateral, an Aquarius venue usable in a strategy route (Aquarius is a supported venue), and enough swap size to move reserves materially within `min_pool_value_wad` and the dual-leg tolerance/sanity bands. The geometric-mean fair-value formula dampens manipulation (sqrt of reserve-ratio change), so the attacker needs a large relative move or a thin pool; the cost is swap fees plus the LP position, recoverable because the bad debt is socialized. One unprivileged address executing `multiply(account_id, spoke_id, lp_collateral, debt_to_flash_loan, debt, mode, crafted_swap, ...)` suffices. If no production market lists an Aquarius-LP-priced collateral, the analog does not bind — that is config-dependent, not code-dependent.

### Recommendation
Re-read (or invalidate) the cached prices for assets whose valuation depends on state the strategy mutated, before `strategy_finalize`. Concretely: after `swap_tokens_or_passthrough` returns, evict `token_prices` entries for assets whose `PriceSource` is `AquariusLp`/`AquariusStableLp` (or whose dependency graph reaches one) and re-fetch in `enforce_post_pool_solvency`. Alternative: record the pool reserve snapshot used by the aggregator and have the solvency gate re-resolve LP keys when reserves changed during the call — mirroring the DeliHook fix of re-pricing at the deduction point.

### Proof of Concept
1. Attacker owns LP shares of an Aquarius constant-product pool (tokenA/tokenB) listed as collateral via `PriceSource::AquariusLp` and supplies them via `supply`.
2. Attacker builds a route `debt.asset → collateral-side` whose hop swaps a large amount of tokenA→tokenB (or the reverse) on that exact Aquarius pool, meeting `total_min_out` for the multiply output leg.
3. Calls `controller.multiply(caller, account_id, spoke_id, collateral=(hub, lp_share_token), debt_to_flash_loan, debt=(hub, borrow_asset), mode=Multiply, swap=route)`. Inside the call: LP price is prefetched at pre-swap reserves, borrow executes, the route skews the pool's reserves (lowering LP fair value), LP output is deposited, and `strategy_finalize` passes `HF >= 1` using the stale high price.
4. Post-transaction, any fresh `get_health_factor`/`is_liquidatable` read shows `HF < 1`; the borrowed tokens are already withdrawn. The position is liquidated/`clean_bad_debt`, and the shortfall is written down against the supply index — a permanent loss to suppliers equal to the manipulated valuation gap.