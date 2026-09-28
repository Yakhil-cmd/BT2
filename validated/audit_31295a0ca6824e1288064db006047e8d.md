### Title
Permanent market freeze: `scaled_to_original` overflows i128 during accrual before the borrow-index cap engages - (File: common/src/rates/scaling.rs)

### Summary
Like CVE-2016-9390 (a crafted input trips an assertion and bricks the parser), a reachable `MathOverflow` panic inside the pool's accrual path bricks an entire market. `accrue_step` computes `borrowed_value = scaled_to_original(borrowed, borrow_index)` before `update_borrow_index` clamps the index to `MAX_BORROW_INDEX_RAY`. On a large high-decimals market at sustained high utilization, the `scaled × index` product overflows `i128` while the index is still below the cap, so every accrue-first entrypoint (`update_indexes`, `supply`, `withdraw`, `borrow`, `repay`, `liquidate`, `clean_bad_debt`, `flash_loan`, `claim_revenue`, `recapitalize`) reverts permanently. The repo already pins this exact scenario in `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs::a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap`.

### Finding Description
`contracts/pool/src/interest.rs::global_sync` runs `accrue_chunk` on every state mutation and on the permissionless `update_indexes` entrypoint. `accrue_chunk` delegates to `common/src/rates/simulate.rs::accrue_step` (lines 51-94), whose first two statements are:

```text
borrowed_original = scaled_to_original(borrowed, borrow_index)   // scaled.mul(index)
supplied_original = scaled_to_original(supplied, supply_index)
```

`scaled_to_original` (`common/src/rates/scaling.rs:14-16`) is `scaled.mul(env, index)`, and `Ray::mul` panics with `GenericError::MathOverflow` on `i128` overflow. The index clamp in `update_borrow_index` (`common/src/rates/index.rs:13-19`) only limits the *index* to `1e36`; it does nothing for the *value* product `scaled × index`, which is bounded by `i128::MAX` (~1.7e38). For a market whose scaled debt book `borrowed` is large relative to `RAY`, the index only needs to reach roughly `i128::MAX / borrowed` — far below `MAX_BORROW_INDEX_RAY` — before the next accrual panics. In the pinned test, a 1-billion-token, 18-decimals market at ~98% utilization on the XLM curve hits the cliff after only a few years of accrual, with `borrow_index ≈ 170×RAY << 1e36` (test lines 316-360).

Crucially, once a single chunk panics, `global_sync` can never complete: `needs_accrual` stays true and every subsequent call recomputes the same overflowing product. The panic is not transient.

### Impact Explanation
**Permanent freezing of funds** for an entire market. Because every controller verb accrues first through `global_sync`, after the cliff:
- Suppliers cannot `withdraw` — supply shares are frozen forever.
- Borrowers cannot `repay` — positions can never be closed.
- `liquidate` and `clean_bad_debt` cannot run — undercollateralized debt becomes uncloseable bad debt, pushing the market toward insolvency rather than resolution.
- `claim_revenue`, `recapitalize`, `flash_loan`, `flash_position`, `multiply` on that asset all revert.

The test demonstrates this directly: after the panic, `try_withdraw_raw` and `try_repay` both fail with `MATH_OVERFLOW` (lines 354-356). All tokens held by the pool for that hub asset become unreachable — a "contract unable to operate" / permanent-freeze impact, not a fail-closed rejection of a single bad input.

### Likelihood Explanation
Medium-low per-market, but structurally reachable by unprivileged actors:

- No privileged action is needed. Any user can `borrow` to push utilization onto the steep segment of the curve, and anyone can call `update_indexes`. A whale (or an attacker using the protocol's own `flash_loan`/leverage legs to maximize borrow share) keeps utilization near the kink, which maximizes `calculate_borrow_rate` and thus index growth per chunk.
- The trigger shrinks with market size and decimals: the cliff index is `i128::MAX / borrowed_scaled`, so the largest markets — the ones holding the most user funds — freeze *first*, well before `MAX_BORROW_INDEX_RAY`.
- The defect is a gap between two bounds: the index is capped at `1e36` but value math is capped at `i128::MAX`. Nothing in `supply`/`borrow` enforces `borrowed_scaled ≤ i128::MAX / MAX_BORROW_INDEX_RAY`, so the book can be grown into the unsafe region through ordinary, permissionless `supply`/`borrow` calls with lifted caps (caps are an admin parameter, not a hard bound at this scale).

### Recommendation
Enforce the product bound at the boundary instead of letting it panic mid-accrual:

1. Cap `borrowed`/`supplied` scaled books so that `scaled × MAX_BORROW_INDEX_RAY` (resp. `MAX_SUPPLY_INDEX_RAY`) fits `i128`. Enforce this in `supply`/`borrow`/accrue paths alongside the existing `max_cap_for_decimals` domain checks, so a book can never grow into the overflow region.
2. Alternatively, saturate rather than panic in `accrue_step`: when `borrowed × new_index` would overflow, clamp `new_index` to `i128::MAX / borrowed` (and clamp accrued interest to the representable delta), preserving the index cap's intent without freezing the market. A saturating `mul_div`-style variant of `scaled_to_original` used only inside accrual/risk reads, with `MathOverflow` kept for entry validation, would keep the panic semantics where they are safe.

Either fix must keep `global_sync` total-over-time monotone so it always completes and unfreezes exits, repayments and liquidations.

### Proof of Concept
Already pinned in-repo: `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:320-361`.

1. Build a market `BIG18` (18 decimals, XLM borrow curve, max-utilization check disabled, caps lifted via `edit_asset_in_spoke_caps` to `max_cap_for_decimals(18)`).
2. `supply(BOB, BIG18, 1e9 * 1e18)`; `supply(ALICE, COL, 3e9 * 1e7)`; `borrow(ALICE, BIG18, 0.98 * principal)` — all ordinary unprivileged calls.
3. Advance ledger time year-by-year, calling the permissionless `update_indexes`. After a few years, `try_update_indexes_for(["BIG18"])` returns `Error(Contract, MATH_OVERFLOW)` with `borrow_index ≈ 170×RAY < MAX_BORROW_INDEX_RAY` — the panic fires inside `scaled_to_original` before the cap clamp.
4. Thereafter `withdraw(BOB, BIG18, 1)` and `repay(ALICE, BIG18, …)` both revert with `MATH_OVERFLOW`, permanently. Same for `liquidate`, `claim_revenue`, `flash_loan` on that asset.