### Title
Oversized supply pushes a market's RAY-value product past i128 and permanently freezes all verbs that accrue - (common/src/rates/index.rs)

### Summary
An unprivileged supplier can deposit an amount close to the admitted supply cap so that `supplied * supply_index` (or the accrued borrow book value) overflows `i128`. Every controller verb syncs interest first, and the sync path panics with `MATH_OVERFLOW` inside `update_supply_index` / `scaled_to_original`. Once crossed, the market is permanently frozen — no supply, borrow, repay, withdraw, liquidate, or `update_indexes` can ever execute for that asset again.

### Finding Description
The bug class in the report is "oversized input causes a system hang". In XOXNO Lending the analog is an oversized *amount* input: `supply` / `repay` / `update_indexes` all route through index math where a RAY-scaled total is multiplied by a RAY index.

- `update_supply_index` computes `total_supplied_value = supplied.mul(env, old_index)`; `Ray::mul` panics on overflow (`MathOverflow`) — `common/src/rates/index.rs:34`.
- The same panic applies on the debt side through `scaled_to_original` = `scaled.mul(env, index)` — `common/src/rates/scaling.rs:14-16`, and position conversions "panic on overflow" by design (`common/src/rates/scaling.rs:24-25`).
- Admission only caps the *token-unit* input: `max_cap_for_decimals` admits up to `i128::MAX / 10^(27-d)` ≈ 170.14 billion whole tokens (`common/tests/validation.rs:374-384`). There is no check that `total_supplied_value + accrual` will still fit the RAY domain at plausible index growth — the docs explicitly admit "valid caps and bounded indexes do not guarantee that future accrual fits. Value overflow can occur before the index ceiling and block repayment/withdrawal because those operations accrue first" (`docs/reference/formulas.md:432-437`).
- The overflow threshold is reachable well below the index ceiling: `supplied(ray) * index` overflows once the market total exceeds `i128::MAX / index`. At index = 1 RAY that is ~1.7e11 whole tokens — exactly the admitted cap maximum — and any accrued index growth lowers the required deposit proportionally. The harness reproduces the cliff end-to-end in `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:321-356`, where a whale book makes `try_update_indexes_for`, `try_withdraw_raw`, and `try_repay` all revert with `MATH_OVERFLOW` while `borrow_index < MAX_BORROW_INDEX_RAY`.

The triggering input is the caller's own `amount` argument to `supply` (and the attacker can deliberately drive utilization/rates high to grow the index faster), so a single unprivileged address with a sufficiently large token holding — realistic for high-supply tokens whose unit price is tiny — can push a market over the cliff.

### Impact Explanation
Permanent freezing of funds: after the product crosses `i128::MAX`, every entrypoint that touches the market accrues first and panics. All suppliers' deposits, borrowers' collateral backing that market, and pending liquidation capacity are frozen indefinitely; `recapitalize` cannot help because it too syncs. This is not a transient or budget DoS — no sequence of calls can recover, since the panicking multiplication happens before any state change and the index/product only grows with time.

### Likelihood Explanation
Requires (a) a listing whose spoke supply cap is near the admitted maximum and (b) an attacker holding on the order of 10^11 whole tokens (or less as the index grows). For high-unit-supply, low-price tokens this is economically feasible — the protocol's own admission bound allows the full 170 billion. Accrual then does the rest: any `update_indexes` call (permissionless keeper entrypoint) triggers the freeze. Medium likelihood; severity-appropriate as Medium.

### Recommendation
Bound admission so the RAY-domain product cannot overflow: either cap `total_supplied` per market to `i128::MAX / MAX_SUPPLY_INDEX_RAY` (≈1.7e2 ray-units, far below the token-unit cap), or reject syncs where `supplied * index` would overflow by clamping accrual the way the index ceiling already does. At minimum, make `update_supply_index` and the borrow-side accrual saturate rather than panic so the market degrades (interest stops) instead of freezing permanently.

### Proof of Concept
1. Governance lists a market with `supply_cap`/`borrow_cap` near `max_cap_for_decimals(d)` and a steep rate curve.
2. Attacker calls `supply(caller, account_id, spoke_id, legs)` depositing ~1.7e11 whole tokens (within cap), then borrows near `max_utilization` to maximize the borrow rate.
3. Any subsequent `update_indexes([asset])` — callable by anyone — computes `supplied.mul(env, index)` / debt `scaled_to_original` and panics `MATH_OVERFLOW`.
4. Thereafter `supply`, `withdraw`, `repay`, `liquidate`, and `claim_revenue` for that asset all panic at the accrual step. Reproduced by `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` (`tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:321`), which asserts `try_update_indexes_for`, `try_withdraw_raw`, and `try_repay` all fail with `errors::MATH_OVERFLOW`.