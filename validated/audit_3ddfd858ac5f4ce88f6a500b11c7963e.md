### Title
`flash_position` final solvency gate reuses prices fetched before the receiver callback, letting the callback revalue collateral between check-time and use-time (TOCTOU / DNS-rebinding analog) - (File: contracts/controller/src/strategies/flash_position.rs)

### Summary
The external report's bug class is "value validated at time A, silently reused at time B after attacker-controlled re-resolution." The same shape exists in `process_flash_position`: `prefetch_strategy_prices` loads all token prices into the invocation-local `Context` *before* the arbitrary receiver callback runs, and `strategy_finalize`'s post-callback risk gates read `cached_price`, which returns the prefetched snapshot without re-fetching. An attacker's receiver contract runs arbitrary external calls in between, so the real market value of the collateral the gate scores can diverge from the cached price it is scored at.

### Finding Description
In `contracts/controller/src/strategies/flash_position.rs`:

- `prefetch_strategy_prices(&mut cache, &account, &extra_assets)` runs at line 117, populating `cache.token_prices` for the debt asset and every declared collateral asset.
- Only then does `storage::with_flash_guard` wrap `invoke_receiver` (lines 120-143), which calls arbitrary attacker-controlled code via `env.invoke_contract(receiver, "execute_flash_position", ...)` (lines 297-323).
- After the callback, deposits are measured and `strategy_finalize` (line 153) runs `require_post_pool_risk_gates` — LTV-weighted collateral coverage, HF ≥ 1, and the min-borrow floor — all valued through `Context::cached_price` (`contracts/controller/src/context.rs:153-160`), which panics on a *missing* entry but never re-fetches an existing one. `fetch_prices` explicitly retains cached entries (`context.rs:141-151`).

So the price used for admission is resolved once, before the callback, and treated as still valid after it. The flash guard blocks reentry into controller/pool monetary entrypoints, but the receiver may freely call *other* contracts — including the Aquarius pools whose reserves feed `PriceSource::AquariusLp` valuations (`contracts/price-aggregator/src/providers/aquarius.rs`). Where an accepted price's derivation includes live, mutable pool state (reserves, LP supply, pool value vs `min_pool_value_wad`), the callback is a "DNS switch": the fetched value was valid at fetch time and stale at gate time. The stale cache only ever *helps* the attacker when it overstates collateral or understates debt relative to post-callback reality — exactly the direction the validation was supposed to prevent.

### Impact Explanation
A receiver that can move an accepted price's inputs during its callback causes the final solvency gate to score the position at pre-callback prices while the account's true collateralization has degraded. The result is an account that passes `strategy_finalize` while undercollateralized at execution-time prices — minted debt that the collateral does not actually cover, i.e., instant bad debt for pool suppliers. This matches the accepted impact classes: protocol insolvency / theft of user funds via undercollateralized borrowing. The debt minted by `borrow_into_controller` is real debt on the pool; nothing later re-checks solvency at corrected prices until a liquidator does, by which point the loss is already booked.

### Likelihood Explanation
Two conditions must hold, and both are plausibly satisfiable but I could not fully verify the second within this review:

1. The caller controls a receiver contract (own flash receiver is in-scope) and calls `flash_position` on their own account. Confirmed reachable.
2. Some listed collateral or debt asset resolves through a price source whose inputs the callback can move within one transaction. `AquariusLpSource` prices derive from live pool reserves; whether a single-transaction reserve manipulation actually moves the *fair value* output depends on the pool math (constant-product fair value is partially manipulation-resistant; dropping pool value below `min_pool_value_wad` yields fail-closed DoS rather than a usable skew). If any market's accepted price path depends on manipulable reserve state — or on a secondary source leg that can be pushed to disagree/be discarded — the analog is exploitable. If every listed market's price is purely signer-mediated (Reflector/RedStone), the cache is stale but not attacker-steerable, and the analog reduces to documented caching behavior (INV-ORACLE-03).

Severity: Medium, conditional on condition 2.

### Recommendation
Re-fetch (or explicitly re-validate) prices after the receiver callback, before `strategy_finalize`'s risk gates — i.e., clear `cache.token_prices` between `invoke_receiver` and `process_deposit`/`strategy_finalize`, or treat pre-callback prices as provisional and require a fresh aggregator `Session` for the final valuation. Alternatively, document and enforce that no listed market may resolve through a price source whose inputs are mutable by the callback within the same transaction.

### Proof of Concept
1. Attacker deploys a receiver contract implementing `execute_flash_position`.
2. Identify a market whose accepted price depends on in-transaction-mutable state (e.g., an `AquariusLpSource` collateral leg).
3. Call `flash_position(caller=attacker, account_id=0, debt=<flashloanable market>, amount=X, receiver=attacker_receiver, collaterals=[(LP_market, min>0)], refund_assets=[debt_token])`.
4. Inside the callback: take the forwarded debt tokens, acquire minimal collateral, manipulate the Aquarius pool reserves/LP state so the collateral's true post-callback value is materially lower than the prefetched price (or so the debt asset's true price is higher), then transfer `min` collateral to the controller.
5. `collect_collateral_deposits` measures the token deltas (unaffected by price), `process_deposit` credits them, and `strategy_finalize` computes LTV/HF using the pre-callback cached prices — passing a position that is underwater at current market state.
6. Attacker walks away with unspent debt tokens via `refund_assets`; the pool carries the bad debt.