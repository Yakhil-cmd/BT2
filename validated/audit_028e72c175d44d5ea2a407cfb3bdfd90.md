### Title
Aquarius LP collateral valued from live pool reserves — donation-based reserve inflation enables over-borrow - (File: contracts/price-aggregator/src/providers/aquarius.rs)

### Summary
An unprivileged attacker who controls a dominant share of an Aquarius pool listed as lending collateral can inflate the pool's reported reserves (`get_reserves`), which `providers::aquarius::read` consumes directly, raising the fair-value LP price used by the controller's health-factor math. The attacker supplies the LP shares, borrows against the inflated valuation, then withdraws liquidity to recover the injected funds, leaving bad debt. This mirrors the Sharwa/Hegic exploit class: collateral priced from a manipulable on-chain pool state rather than an independent oracle.

### Finding Description
`providers::aquarius::read` (contracts/price-aggregator/src/providers/aquarius.rs:69-131) prices an LP share as `fair_lp_price_wad` / `fair_stable_lp_price_wad` using **live** `aquarius_pool_reserves_call` and `aquarius_total_shares_call` (lines 90-93). `aquarius_pool_reserves_call` (common/src/oracle/providers/aquarius.rs:45-57) is a direct cross-contract `get_reserves` read inside the same transaction — no TWAP, no smoothing.

The fair-value formulas are swap-resistant but not donation-resistant:

- Constant product (`common/src/oracle/lp.rs:57-87`): `price = 2 * sqrt(value_a * value_b) / share_supply`. A balanced swap preserves `value_a * value_b`, but pushing extra `token_a`/`token_b` into the pool without minting shares strictly increases the geometric mean — the share price rises ~`sqrt(1 + donation/pool_value)`.
- Stable (`common/src/oracle/lp_stable.rs:80-110`): `price = D * min(price_a, price_b) / share_supply`. `D` grows monotonically with reserve inflation at fixed external leg prices.

Crucially, the usual backstops are waived for LP oracles: `validate_asset_oracle` (contracts/price-aggregator/src/admin.rs:157-197) skips `smoothing` and `validate_oracle_tolerance` when `has_aquarius_lp_source()`, and LP sources are sole-source by construction (admin.rs:181-184, `SourceCountOutOfRange` if combined), so there is no independent anchor leg to disagree with the manipulated value. The only remaining bound is the configured sanity band `[min_sanity_price_wad, max_sanity_price_wad]` — but any inflation up to the ceiling is accepted, and for a manipulation inside the band the price is treated as canonical WAD risk input by the controller's `Context`-cached valuation.

The exploit path is fully unprivileged and mirrors the reference attack shape:

1. Acquire a dominant fraction of the target Aquarius pool's LP shares (thin pool; `min_pool_value_wad` only requires the pool clear a floor, not that ownership be dispersed).
2. `flash_loan` on the controller (or external flash) to obtain leg tokens.
3. Transfer leg tokens into the Aquarius pool (donation; or skewed `deposit` on a venue that credits reserves without proportional share dilution), inflating `get_reserves` while `total_shares` stays fixed.
4. `supply` the LP shares / call `borrow` — the controller resolves the LP collateral price through `prices`, reading the now-inflated reserves within the same transaction.
5. Borrow the maximum across debt markets, `withdraw` borrowed assets.
6. Remove liquidity to recover a `shares/total_shares` fraction of the donation; repay the flash loan; default on the borrow.

Net cost ≈ `donation * (1 - attacker_share_fraction)` + fees; net gain = borrowed value exceeding true collateral value.

### Impact Explanation
Theft of pool funds / protocol insolvency: borrows are opened at an LTV computed against an inflated collateral price, so realized debt exceeds recoverable collateral value. Any LP-token collateral market whose underlying Aquarius pool can be reserve-inflated by an unprivileged account is exposed; the stolen amount scales with the gap between the manipulated price and the true price, up to the sanity ceiling.

### Likelihood Explanation
Requires the attacker to hold a large share of the LP token and enough capital (flash-borrowable) to move the fair price within the sanity band. Feasible for thin or concentrated pools; `min_pool_value_wad` filters dust pools but does not bound ownership concentration. Uncertainty: the attack depends on Aquarius `get_reserves` reflecting transferred balances (or on a deposit path that credits reserves without proportional share issuance); if Aquarius tracks reserves as internal counters immune to raw transfers, the inflation leg must instead go through the pool's own deposit/swap interface, which may reduce but not eliminate the asymmetry for an attacker holding most of the shares. The stable-pool test `swap_cannot_move_the_price` confirms swaps alone don't move the price — donation is the required primitive.

### Recommendation
- Do not rely solely on live `get_reserves` for LP collateral pricing; bound the accepted fair price by an independently-anchored reference (dual-source tolerance leg or a smoothed/TWAP'd reserve snapshot).
- Tighten LP sanity bands so the ceiling sits at or below `1/LTV` of expected fair value, making an in-band over-borrow unprofitable.
- Require `min_pool_value_wad` plus an ownership-concentration-aware listing criterion, or derive reserves from cumulative pool accounting rather than raw balances where the venue supports it.

### Proof of Concept
```text
Attacker (unprivileged), single transaction on Stellar:
1. controller.flash_loan(token_a_amount)
2. token_a.transfer(AQUARIUS_POOL, token_a_amount)        // inflates get_reserves()[0]
   // price_wad(share) now ~ sqrt(1 + donation/V) * honest_price, <= max_sanity_price_wad
3. controller.supply(lp_share_token, attacker_lp_shares) // collateral
4. controller.borrow(debt_token, max_amount)             // Context prices LP at inflated value
5. controller.withdraw(debt_token, max_amount)
6. aquarius_pool.withdraw(...)                           // burn LP shares, recover ~share% of donation
7. repay flash loan; keep residual borrowed tokens; abandon account debt
```
Root cause locations: `aquarius_pool_reserves_call` live read (common/src/oracle/providers/aquarius.rs:45-57), donation-sensitive fair pricing (common/src/oracle/lp.rs:57-87, common/src/oracle/lp_stable.rs:80-110), and the LP-specific waiver of smoothing/dual-source tolerance in `validate_asset_oracle` (contracts/price-aggregator/src/admin.rs:157-197).