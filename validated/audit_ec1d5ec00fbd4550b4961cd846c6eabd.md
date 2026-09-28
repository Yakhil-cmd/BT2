### Title
Debt-scaled × index product overflows `i128` before the borrow-index cap engages, permanently freezing the market - (File: common/src/rates/index.rs)

### Summary
Every mutating pool verb accrues interest first via `interest::global_sync` → `accrue_chunk` → `accrue_step`, which multiplies the scaled debt `borrowed` (a RAY-precision `Ray`) by `borrow_index` through `Ray::mul` / `scaled_to_original`. That product is an `i128` checked multiplication. `update_borrow_index` caps the *index* at `MAX_BORROW_INDEX_RAY`, but nothing caps the *value product* `borrowed * borrow_index`. Once a market's scaled debt is large enough, index growth pushes the product past `i128::MAX`, `Ray::mul` panics with `MathOverflow`, and the panic precedes every supply, borrow, withdraw, repay, liquidation, bad-debt cleanup, and `update_indexes` on that market. The market is permanently frozen: suppliers cannot exit and borrowers cannot repay.

### Finding Description
- `contracts/pool/src/interest.rs:20-53` — `global_sync` runs `accrue_chunk` for every elapsed chunk before any operation proceeds; there is no catch/recover path.
- `common/src/rates/index.rs:80-83` — `calculate_supplier_rewards` computes `borrowed.mul(env, old_borrow_index)` and `borrowed.mul(env, new_borrow_index)`, both checked `i128` products in RAY space.
- `common/src/rates/index.rs:13-19` — `update_borrow_index` clamps only the index itself at `MAX_BORROW_INDEX_RAY`; the cap is applied after the multiplication that produces the new index and never bounds `borrowed * index`.
- `common/src/rates/scaling.rs:14-16` — `scaled_to_original` (used by `unscale_borrow*`, `calculate_utilization`, `require_backed_market`, `guards.rs`) multiplies scaled debt by the index the same way, so even paths that skip rewards math still hit the overflow.
- The product in question is `scaled_raw * index_raw / RAY`. For an 18-decimal market, `scaled_raw ≈ amount × 10^9 / index`; the overflow boundary is reached when the RAY-denominated debt value (`amount × 10^(27−decimals) × index_growth`) crosses ~`1.7e38`. Confirmed reachable in-repo: `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:316-361` shows a whale market at 98% utilization on a steep rate curve hitting `MATH_OVERFLOW` inside accrual while `borrow_index < MAX_BORROW_INDEX_RAY`, after which both `withdraw` and `repay` revert with the same error because they accrue first.

Because the panic happens during accrual — before any state mutation or token transfer — no verb on that `(hub_id, asset)` book can execute again, including `clean_bad_debt`/`seize` (`contracts/pool/src/ops/seize.rs:18-35` calls `synced_market`, which accrues) and `update_indexes` (`contracts/pool/src/ops/market.rs:65-73` accrues unconditionally). There is no admin escape hatch that skips accrual; `replace_rate_model` also accrues under the old model first (`market.rs:52-58`).

### Impact Explanation
Permanent freezing of all funds in the affected market: supplier principal, unclaimed yield, and liquidation access to underwater debt are all locked. Borrowers' collateral in other markets is also at risk because liquidation of positions that touch the frozen market's debt cannot settle that leg. This is exactly the availability class of the CVE (remote, unprivileged-triggerable denial of the core engine) mapped onto the share/index accrual path.

### Likelihood Explanation
A single unprivileged address can drive this via `borrow` (controller) plus waiting: the requirement is a very large outstanding scaled debt and sustained high utilization, not privileged access. For high-decimal, high-supply assets the required notional is economically feasible (stablecoin-style supply of ~10^11+ units at 18 decimals), and no index cap, utilization cap, or borrow cap prevents the *value* overflow — `require_cap_within_asset_domain` only bounds caps to the asset's own domain, which can extend to `i128::MAX`. Medium, matching the source CVE: high impact on one market but conditional on scale and time.

### Recommendation
Make the debt-value computation overflow-safe instead of panic-on-overflow:
- In `calculate_supplier_rewards` (`common/src/rates/index.rs`), compute `new_total_debt`/`old_total_debt` with saturating or `U256` arithmetic and clamp the index increment so `borrowed * new_borrow_index` stays within `i128` — i.e., enforce the ceiling on the product, not just on `MAX_BORROW_INDEX_RAY`.
- Alternatively, enforce a market-level invariant `borrowed ≤ i128::MAX / MAX_BORROW_INDEX_RAY` at debt-mint time (`mint_debt` in `contracts/pool/src/ops/borrow.rs:63-79`), rejecting borrows that would put the market within one accrual step of the value ceiling.

### Proof of Concept
The repository already contains the witness: `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` (`tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:321-361`). It supplies `BILLION * 10^18` units of an 18-decimal asset, borrows 98% of it, advances time year-by-year, and observes `update_indexes` fail with `MATH_OVERFLOW` while `last.borrow_index < MAX_BORROW_INDEX_RAY`. It then asserts `try_withdraw_raw` and `try_repay` both fail with `MATH_OVERFLOW`, demonstrating the market can never be un-frozen — the accrual panic precedes every exit, repayment, liquidation, and cleanup entrypoint.