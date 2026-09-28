### Title
Accrual overflow in `scaled_to_original` permanently freezes a high-utilization market before the index cap engages - (File: contracts/pool/src/cache/scale.rs)

### Summary
The analog of CVE-2018-17358 (a crash on a crafted input that makes the program unusable) is an arithmetic-overflow abort inside interest accrual: once the product `scaled_shares * borrow_index` exceeds `i128`, `scaled_to_original` panics with `MathOverflow`, and because every state-changing entrypoint accrues first, the market becomes permanently frozen — no `repay`, `withdraw`, `borrow`, or `liquidate` can execute. The `MAX_BORROW_INDEX_RAY` cap never gets a chance to clamp the index because the value product overflows earlier.

### Finding Description
`Cache::calculate_utilization` and the unscale helpers in `contracts/pool/src/cache/scale.rs` (lines 19-92) call `common::rates::scaled_to_original`, which multiplies scaled RAY shares by the RAY index and converts to asset units. On a large market at sustained high utilization, the borrow index grows past ~170x while `borrowed_scaled_ray` is near its cap-bounded maximum; the next accrual overflows inside `scaled_to_original` before the stored index reaches `MAX_BORROW_INDEX_RAY`, so the documented index ceiling does not protect the multiplication. The harness test `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` in `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs` (lines 316-361) demonstrates this end-to-end: after the overflow, `try_update_indexes_for`, `try_withdraw_raw`, and `try_repay` all fail with `MATH_OVERFLOW`, and the comment notes "the market is frozen: no repay, no withdraw, no liquidation." The same overflow ordering appears in `SpokeUsageContext::apply_entry` (`contracts/controller/src/spoke_usage.rs`), where the usage-plus-delta add overflows before the cap comparison runs (`contracts/controller/tests/spoke.rs:286-315`).

### Impact Explanation
Permanent freezing of funds and effective protocol insolvency for the affected market: suppliers cannot withdraw, borrowers cannot repay, liquidators cannot liquidate, and `clean_bad_debt`/`recapitalize` paths that touch the market's cache also accrue and hit the same panic. All tokens physically held in the pool book for that market become unreachable.

### Likelihood Explanation
Reachable by any unprivileged address that can supply and borrow — no privileged role is needed. The barrier is economic: it requires a whale-scale position (the test uses ~10^28 base units) and sustained near-max utilization over a long horizon at a steep curve segment, plus caps high enough to admit the position. Because utilization and borrow demand are attacker-influenceable (a whale can borrow to 98%+ and simply not repay), the attacker controls the trigger conditions once capital is committed. Medium severity: high impact, non-trivial capital and market-condition prerequisites.

### Recommendation
- In `scaled_to_original` / `mul_ceil` paths used by accrual, clamp the index to `MAX_BORROW_INDEX_RAY` **before** the multiplication, or perform the unscale in a wider intermediate (e.g., `I256`) and saturate/error only on the final asset-unit result that genuinely cannot fit.
- Order cap checks before arithmetic in `SpokeUsageContext::apply_entry` (compare `cap - current` against `delta` rather than `current + delta` against `cap`).
- Add a regression path where a market near the value ceiling still accepts a repay/withdraw sized below the overflowing product.

### Proof of Concept
The existing harness test is the PoC: `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:320-361` supplies `BILLION * 10^18` of an 18-decimal asset, borrows 98% of it, advances ledger time year-by-year, and observes `update_indexes`, `withdraw`, and `repay` all revert with `MathOverflow` while `borrow_index < MAX_BORROW_INDEX_RAY`. An unprivileged attacker reproduces this on mainnet by supplying a large position, borrowing to ~98% utilization, and waiting; the first accrual after the product crosses `i128::MAX` bricks the market permanently.

Uncertainty note: the test lifts supply/borrow caps, so on a production deployment feasibility depends on the configured caps permitting a large enough scaled position — if caps keep `scaled * index` comfortably under `i128::MAX` for all listed markets, impact reduces to a latent edge case rather than a live freeze.